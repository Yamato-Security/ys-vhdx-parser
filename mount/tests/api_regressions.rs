// Copyright (C) 2026 Shirofune Security Co., Ltd.
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

//! Regression cases for generic disk inputs and shared FUSE unmount handles.

#![cfg(target_os = "linux")]
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::{Arc, Mutex};
use ys_vhdx_mount::{image::Image, image_mount};

#[test]
fn invalid_sector_geometry_returns_an_error_instead_of_panicking() {
    let mut mbr = vec![0u8; 512];
    mbr[510..512].copy_from_slice(&[0x55, 0xAA]);
    mbr[450] = 7;
    mbr[454..458].copy_from_slice(&2u32.to_le_bytes());
    mbr[458..462].copy_from_slice(&1u32.to_le_bytes());
    let result =
        std::panic::catch_unwind(|| Image::from_disk(Box::new(Cursor::new(mbr)), 512, 1u64 << 63));
    assert!(
        result.is_ok(),
        "from_disk panicked on caller-supplied sector geometry"
    );
    assert_eq!(
        result.unwrap().err().unwrap().kind(),
        std::io::ErrorKind::InvalidInput
    );
}

#[test]
fn raw_disk_mount_has_a_working_unmount_handle() {
    let available = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/fuse")
        .is_ok()
        && std::process::Command::new("fusermount3")
            .arg("-V")
            .output()
            .is_ok_and(|o| o.status.success());
    if !available {
        assert!(
            std::env::var("JUNTEI_REQUIRE_FUSE").as_deref() != Ok("1"),
            "FUSE is required"
        );
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fixture.vhdx");
    let fixture = fs::File::open(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("test_files/vhdx/kape-sample.vhdx.gz"),
    )
    .unwrap();
    std::io::copy(
        &mut flate2::read::GzDecoder::new(fixture),
        &mut fs::File::create(&path).unwrap(),
    )
    .unwrap();
    let original = fs::read(&path).unwrap();
    let mut reader = vhdx::VhdxReader::open(&path).unwrap();
    let size = reader.virtual_disk_size();
    let sector = u64::from(reader.logical_sector_size());
    let mut raw = Vec::new();
    reader.read_to_end(&mut raw).unwrap();
    let opened = Image::from_disk(Box::new(Cursor::new(raw)), size, sector).unwrap();
    let point = directory.path().join("mount");
    fs::create_dir(&point).unwrap();
    let unmounters = Arc::new(Mutex::new(Vec::new()));
    let mounted = image_mount::mount_image(opened, &path, &point, &unmounters).unwrap();
    assert_eq!(
        fs::read(point.join("C/Users/sample/Data/small.txt")).unwrap(),
        b"resident content\n"
    );
    assert!(fs::write(point.join("forbidden.txt"), b"no writes").is_err());
    unmounters.lock().unwrap()[0].unmount().unwrap();
    let still_attached = fs::read_to_string("/proc/self/mountinfo")
        .unwrap()
        .contains(point.to_str().unwrap());
    mounted.unmount().unwrap(); // Clean up before the assertion can fail.
    assert_eq!(original, fs::read(&path).unwrap());
    assert!(
        !still_attached,
        "SessionUnmounter returned Ok but the mount was still attached"
    );
}

#[test]
fn invalid_sector_sizes_are_rejected_and_small_sizes_keep_the_documented_default() {
    for sector in [513, 768, 4097, 8192, 1u64 << 63, u64::MAX] {
        let result = Image::from_disk(Box::new(Cursor::new(vec![0; 512])), 512, sector);
        assert_eq!(
            result.err().unwrap().kind(),
            std::io::ErrorKind::InvalidInput,
            "sector {sector}"
        );
    }
    for sector in [0, 1, 256, 511, 512, 1024, 2048, 4096] {
        let result = Image::from_disk(Box::new(Cursor::new(vec![0; 512])), 512, sector);
        // The zero-filled disk has valid geometry but no NTFS volume.
        assert_eq!(
            result.err().unwrap().kind(),
            std::io::ErrorKind::InvalidData,
            "sector {sector}"
        );
    }
}
