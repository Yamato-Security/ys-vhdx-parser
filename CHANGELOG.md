# Changes

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
