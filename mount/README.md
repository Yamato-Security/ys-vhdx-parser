# ys-vhdx-mount

Read-only NTFS/FUSE mounting for Yamato Security's [VHDX SDK](../README.md), extracted
from Juntei PR #135. The API is available on Linux; the container reader in `core/`
is cross-platform. This crate is licensed under RPL-1.5; see [LICENSE](LICENSE).

- `image::Image::open`: read VHDX and discover NTFS volumes; inspect `problems` for
  any partitions that could not be opened.
- `image::Volume`: enumerate files, read standard-information timestamps and serve
  arbitrary-offset resident, fragmented, sparse and compressed content.
- `image_mount::new_session`: construct a read-only FUSE session.
- `image_mount::mount`: start a background mount, returned as `Mounted`.
- `Mounted::unmount`: unmount and join the worker threads; dropping it also unmounts.
- `image_mount::unmount_on_interrupt`: opt in to a process-wide signal handler.

FUSE 3 and `/dev/fuse` are required for mounting. Do not install multiple process-wide
interrupt handlers. The CLI and orchestration remain in Juntei.

The VHDX reader is the workspace's `ys-vhdx-parser`; `ntfs-core`, `fuser` and `ctrlc`
provide NTFS decoding, the FUSE protocol and signal delivery respectively. Source
images are opened read-only and writes through the mount are refused.
