# ys-vhdx-parser

The cross-platform VHDX container reader in Yamato Security's
[ys-vhdx-parser workspace](../README.md). The Rust library name remains `vhdx`.

This is the tested `vhdx-core` 0.4.1 reader from Security Ronin, imported at commit
`40358d3153c121dcea986a125fa6a8f88853bc1e`, with its implementation, tests, Apache-2.0
license and attribution retained. `Cargo.toml` uses the Yamato package/repository
name. See [NOTICE](../NOTICE), [LICENSE](LICENSE) and the [original README](README.original.md).

The separate [`ys-vhdx-mount`](../mount/) crate adds NTFS/FUSE mounting for Juntei.
