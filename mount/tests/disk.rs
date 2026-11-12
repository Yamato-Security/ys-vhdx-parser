// Copyright (C) 2026 Shirofune Security Co., Ltd.

// SPDX-License-Identifier: RPL-1.5 OR AGPL-3.0-only
//
// You may alternatively use this file under the GNU Affero General Public License,
// version 3 only; see LICENSE-AGPL-3.0. The following notice applies to the RPL option.
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! A disk read by the caller (`Image::from_disk`): the whole disk with its partition table, and a
//! single volume without one, read as the VHDX itself is.

use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use ys_vhdx_mount::image::{Image, ROOT_RECORD, Volume};

/// The fixture's VHDX, decompressed into `directory`.
fn sample(directory: &Path) -> PathBuf {
    let image = directory.join("sample.vhdx");
    let fixture = fs::File::open(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("test_files/vhdx/sample.vhdx.gz"),
    )
    .unwrap();
    std::io::copy(
        &mut flate2::read::GzDecoder::new(fixture),
        &mut fs::File::create(&image).unwrap(),
    )
    .unwrap();
    image
}

/// The content of the file at `path` (names separated by `/`) in `volume`.
fn read_file(volume: &Volume, path: &str) -> Vec<u8> {
    let mut record = ROOT_RECORD;
    for name in path.split('/') {
        record = volume.lookup(record, name).unwrap().unwrap().record;
    }
    let size = volume.stat(record).unwrap().size;
    volume
        .read(record, 0, usize::try_from(size).unwrap())
        .unwrap()
}

#[test]
fn a_disk_from_another_reader_reads_as_the_vhdx_does() {
    let directory = tempfile::tempdir().unwrap();
    let path = sample(directory.path());
    let opened = Image::open(&path).unwrap();
    let mut disk = Vec::new();
    vhdx::VhdxReader::open(&path)
        .unwrap()
        .read_to_end(&mut disk)
        .unwrap();
    assert_eq!(disk.len() as u64, opened.size);

    let from_disk =
        Image::from_disk(Box::new(Cursor::new(disk.clone())), opened.size, 512).unwrap();
    assert_eq!(from_disk.size, opened.size);
    let layout = |image: &Image| -> Vec<(u64, u64)> {
        image.volumes.iter().map(|v| (v.start, v.len)).collect()
    };
    assert_eq!(layout(&from_disk), layout(&opened));
    let file = "C/Users/sample/Data/fragmented.bin";
    assert_eq!(
        read_file(&from_disk.volumes[0], file),
        read_file(&opened.volumes[0], file)
    );

    // An image of the volume alone, without a partition table, is one volume from byte 0.
    let volume = &opened.volumes[0];
    let start = usize::try_from(volume.start).unwrap();
    let end = start + usize::try_from(volume.len).unwrap();
    let alone = disk[start..end].to_vec();
    let from_volume = Image::from_disk(Box::new(Cursor::new(alone)), volume.len, 512).unwrap();
    assert_eq!(layout(&from_volume), [(0, volume.len)]);
    assert_eq!(
        read_file(&from_volume.volumes[0], "C/Users/sample/Data/small.txt"),
        b"resident content\n"
    );
}

#[test]
fn a_disk_without_ntfs_is_refused() {
    let zeros = vec![0_u8; 1 << 20];
    let error = Image::from_disk(Box::new(Cursor::new(zeros)), 1 << 20, 512)
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "no NTFS volume found");
}

#[test]
fn file_readers_stream_and_seek_each_ntfs_storage_layout() {
    use std::io::{Seek, SeekFrom};
    use std::sync::Arc;
    let directory = tempfile::tempdir().unwrap();
    let path = sample(directory.path());
    let original = fs::read(&path).unwrap();
    let image = Arc::new(Image::open(&path).unwrap());
    for file in [
        "small.txt",
        "fragmented.bin",
        "sparse.bin",
        "compressed/text.log",
    ] {
        let name = format!("C/Users/sample/Data/{file}");
        let expected = read_file(&image.volumes[0], &name);
        let mut record = ROOT_RECORD;
        for part in name.split('/') {
            record = image.volumes[0]
                .lookup(record, part)
                .unwrap()
                .unwrap()
                .record;
        }
        let mut stream = image.file_reader(0, record).unwrap();
        let mut model = Cursor::new(expected.clone());
        assert_eq!(stream.len(), expected.len() as u64);
        for (seek, length) in [
            (SeekFrom::Start(0), 4096),
            (SeekFrom::Start(7), 17),
            (SeekFrom::End(-5), 16),
            (SeekFrom::Current(-2), 2),
            (SeekFrom::Start(stream.len() + 10), 100),
        ] {
            assert_eq!(stream.seek(seek).unwrap(), model.seek(seek).unwrap());
            let mut actual = vec![0; length];
            let mut wanted = vec![0; length];
            let got = stream.read(&mut actual).unwrap();
            let want = model.read(&mut wanted).unwrap();
            assert_eq!(got, want, "{file}");
            assert_eq!(&actual[..got], &wanted[..want], "{file}");
        }
        assert!(
            stream
                .seek(SeekFrom::End(-((stream.len() as i64) + 1)))
                .is_err()
        );
        stream.rewind().unwrap();
        let mut all = Vec::new();
        stream.read_to_end(&mut all).unwrap();
        assert_eq!(all, expected, "{file}");
    }
    assert!(image.file_reader(usize::MAX, ROOT_RECORD).is_err());
    assert!(image.file_reader(0, ROOT_RECORD).is_err());
    assert_eq!(original, fs::read(&path).unwrap());
}

#[test]
fn independent_readers_keep_the_image_alive_and_are_sendable() {
    use std::sync::Arc;
    let directory = tempfile::tempdir().unwrap();
    let path = sample(directory.path());
    let image = Arc::new(Image::open(&path).unwrap());
    let mut record = ROOT_RECORD;
    for part in "C/Users/sample/Data/small.txt".split('/') {
        record = image.volumes[0]
            .lookup(record, part)
            .unwrap()
            .unwrap()
            .record;
    }
    let mut first = image.file_reader(0, record).unwrap();
    let mut second = image.file_reader(0, record).unwrap();
    drop(image);
    let worker = std::thread::spawn(move || {
        let mut data = Vec::new();
        first.read_to_end(&mut data).unwrap();
        data
    });
    let mut data = Vec::new();
    second.read_to_end(&mut data).unwrap();
    assert_eq!(data, b"resident content\n");
    assert_eq!(worker.join().unwrap(), data);
}
