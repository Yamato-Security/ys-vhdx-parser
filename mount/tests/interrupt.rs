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

//! Real process interruption tests; mounts contain only the public SDK fixture.
#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use ys_vhdx_mount::image_mount;

fn available() -> bool {
    let ok = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/fuse")
        .is_ok()
        && Command::new("fusermount3")
            .arg("-V")
            .output()
            .is_ok_and(|o| o.status.success());
    assert!(
        ok || std::env::var("JUNTEI_REQUIRE_FUSE").as_deref() != Ok("1"),
        "FUSE is required"
    );
    ok
}
fn fixture(directory: &Path) -> PathBuf {
    let image = directory.join("fixture.vhdx");
    let file = fs::File::open(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("test_files/vhdx/kape-sample.vhdx.gz"),
    )
    .unwrap();
    std::io::copy(
        &mut flate2::read::GzDecoder::new(file),
        &mut fs::File::create(&image).unwrap(),
    )
    .unwrap();
    image
}
fn attached(points: &Path) -> bool {
    fs::read_to_string("/proc/self/mountinfo")
        .unwrap()
        .contains(points.to_str().unwrap())
}
// Kill/reap the helper on assertion failures and detach only this test's owned mounts.
struct ChildMounts {
    child: Child,
    points: PathBuf,
}
impl Drop for ChildMounts {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if attached(&self.points) {
            for index in 0..32 {
                let _ = Command::new("fusermount3")
                    .args(["-u", "-z", "--"])
                    .arg(self.points.join(format!("image-{index}")))
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }
}

#[test]
#[ignore = "subprocess helper; invoked by interrupts_detach_images_during_mount_registration"]
fn interrupt_child() {
    let root = PathBuf::from(std::env::var_os("YS_VHDX_INTERRUPT_TEST_ROOT").unwrap());
    let points = root.join("points");
    let registry = Arc::new(Mutex::new(Vec::new()));
    image_mount::unmount_on_interrupt(registry.clone(), Some(points.clone()), Some(130)).unwrap();
    let mut images = Vec::new();
    for index in 0..32 {
        images.push(
            image_mount::mount(
                &root.join("fixture.vhdx"),
                &points.join(format!("image-{index}")),
                &registry,
            )
            .unwrap(),
        );
    }
    loop {
        std::thread::park();
    }
}

#[test]
fn interrupts_detach_images_during_mount_registration() {
    if !available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let image = fixture(root.path());
    let original = fs::read(&image).unwrap();
    for signal in ["-INT", "-TERM", "-HUP"] {
        let points = root.path().join("points");
        // Pre-create the caller-owned empty directories before installing the handler.
        for index in 0..32 {
            fs::create_dir_all(points.join(format!("image-{index}"))).unwrap();
        }
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "interrupt_child", "--nocapture"])
            .env("YS_VHDX_INTERRUPT_TEST_ROOT", root.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut guard = ChildMounts {
            child,
            points: points.clone(),
        };
        let start = Instant::now();
        while !attached(&points) {
            assert!(
                guard.child.try_wait().unwrap().is_none(),
                "helper exited before mounting"
            );
            assert!(start.elapsed() < Duration::from_secs(30), "mount timed out");
            std::thread::sleep(Duration::from_millis(2));
        }
        // Keep a file open outside the helper to exercise lazy detach on a busy filesystem.
        let _open_log =
            fs::File::open(points.join("image-0/C/Users/sample/Data/small.txt")).unwrap();
        assert!(
            Command::new("kill")
                .args([signal, &guard.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        while guard.child.try_wait().unwrap().is_none() {
            assert!(
                start.elapsed() < Duration::from_secs(45),
                "interrupt cleanup timed out"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(guard.child.wait().unwrap().code(), Some(130));
        assert!(!attached(&points), "a mount remained after {signal}");
        assert!(
            !points.exists(),
            "empty mount directories remained after {signal}"
        );
        assert_eq!(
            original,
            fs::read(&image).unwrap(),
            "evidence changed after {signal}"
        );
    }
}
