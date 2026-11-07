# Changes

## Initial import

- Preserve the `vhdx-core` 0.4.1 reader and tests as `ys-vhdx-parser`.
- Extract Juntei's read-only NTFS/FUSE implementation into `ys-vhdx-mount`, including
  bounded deferred decompression, checked partition offsets, cycle detection,
  partial-volume diagnostics and precise FILETIME conversion.
- Keep the component licenses and original public test-data attribution.
