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

//! A real FUSE mount through the public SDK, including integrity and write-refusal checks.

#![cfg(target_os = "linux")]

use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use ys_vhdx_mount::image_mount;

fn sha256(path: &Path) -> String {
    Sha256::digest(fs::read(path).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn fuse_available() -> bool {
    let usable = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/fuse")
        .is_ok()
        && Command::new("fusermount3")
            .arg("-V")
            .output()
            .is_ok_and(|o| o.status.success());
    if !usable {
        assert!(
            std::env::var("JUNTEI_REQUIRE_FUSE").as_deref() != Ok("1"),
            "FUSE is required but /dev/fuse or fusermount3 is unavailable"
        );
        eprintln!("FUSE unavailable; set JUNTEI_REQUIRE_FUSE=1 to require this test");
    }
    usable
}

#[test]
fn mount_reads_known_content_refuses_writes_and_preserves_image() {
    if !fuse_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("sdk-mount-test.vhdx");
    let fixture = fs::File::open(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("test_files/vhdx/kape-sample.vhdx.gz"),
    )
    .unwrap();
    std::io::copy(
        &mut flate2::read::GzDecoder::new(fixture),
        &mut fs::File::create(&image).unwrap(),
    )
    .unwrap();
    let original_hash = sha256(&image);
    let point = directory.path().join("mnt");
    fs::create_dir(&point).unwrap();
    let unmounters = Arc::new(Mutex::new(Vec::new()));
    // Mounted also unmounts on drop if an assertion panics.
    let mounted = image_mount::mount(&image, &point, &unmounters).unwrap();
    assert_eq!(mounted.volumes.len(), 1);
    assert!(mounted.problems.is_empty(), "{:?}", mounted.problems);
    assert_eq!(unmounters.lock().unwrap().len(), 1);
    let data = point.join("C/Users/sample/Data");
    assert_eq!(
        fs::read(data.join("small.txt")).unwrap(),
        b"resident content\n"
    );
    assert_eq!(
        sha256(&data.join("fragmented.bin")),
        "dad53fd22d62e1acbf48ababc172c8eb3ffb45486b261fb960a2990199a8e459"
    );
    assert_eq!(
        sha256(&data.join("compressed/text.log")),
        "cc3c52b090233f44ecfc2dbd90adc6c787e071872ca488fa96eae24af8162f98"
    );
    assert!(data.join("日本語のファイル.txt").is_file());
    assert!(
        fs::metadata(data.join("small.txt"))
            .unwrap()
            .permissions()
            .readonly()
    );
    assert!(fs::write(data.join("new.txt"), b"x").is_err());
    assert!(
        fs::OpenOptions::new()
            .write(true)
            .open(data.join("small.txt"))
            .is_err()
    );
    assert!(fs::remove_file(data.join("small.txt")).is_err());
    mounted.unmount().unwrap();
    assert!(
        !data.exists(),
        "the FUSE view must disappear after unmounting"
    );
    assert_eq!(
        sha256(&image),
        original_hash,
        "mounting must not alter evidence"
    );
}
