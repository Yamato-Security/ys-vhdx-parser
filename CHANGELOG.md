# Changes

## Unreleased

- Make `ys-vhdx-mount::image` available on Linux, macOS, and Windows, including NTFS
  traversal and seekable `Image::file_reader` streams. Direct reads require no FUSE
  driver, mount helper, administrator privileges, or temporary extraction. Linux
  FUSE mounting remains available through `image_mount`.

- Reject invalid logical sector sizes in `Image::from_disk` and check MBR/EBR byte-range
  arithmetic so malformed geometry returns an error instead of panicking or wrapping.
- Keep FUSE mount ownership shared with registered unmount handles instead of moving it
  into `BackgroundSession`. Interrupt callbacks now actually detach mounted images;
  mount creation/registration is serialized with interrupt cleanup and process exit.

- `ys-vhdx-mount`: `image::Image::from_disk` opens the NTFS volumes of a disk that the caller
  reads from any other container (any `Read + Seek + Send`), such as an E01 image, and
  `image_mount::mount_image` mounts an opened image. A disk that is a single NTFS volume
  without a partition table is one volume, as for VHDX. (Juntei #140)

## 1.0.0 - 2026-11-07

- Version both `ys-vhdx-parser` and `ys-vhdx-mount` as 1.0.0 through shared workspace metadata.
- Use Rust edition 2024 and Cargo resolver 3 for both crates.
- Update dependency requirements and the lockfile, including `forensic-vfs` 0.10 and
  `sha2` 0.11. Rust 1.88 or newer is required, matching the updated hash dependency.

## Initial import

- Preserve the `vhdx-core` 0.4.1 reader and tests as `ys-vhdx-parser`.
- Extract Juntei's read-only NTFS/FUSE implementation into `ys-vhdx-mount`, including
  bounded deferred decompression, checked partition offsets, cycle detection,
  partial-volume diagnostics and precise FILETIME conversion.
- Keep the component licenses and original public test-data attribution.
