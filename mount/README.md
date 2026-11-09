# ys-vhdx-mount

Read-only NTFS/FUSE mounting for Yamato Security's [VHDX SDK](../README.md), extracted
from Juntei PR #135. The API is available on Linux; the container reader in `core/`
is cross-platform. This crate is dual-licensed under **RPL-1.5 OR AGPL-3.0-only**, at your choice; see
[LICENSE](LICENSE) and [LICENSE-AGPL-3.0](LICENSE-AGPL-3.0). The AGPL alternative lets
Hayabusa reuse the same read-only mounting implementation.

- `image::Image::open`: read VHDX and discover NTFS volumes; inspect `problems` for
  any partitions that could not be opened.
- `image::Image::from_disk`: the same for a disk that the caller reads from another
  container (an E01 image, for example), given as any `Read + Seek + Send`. Logical
  sector sizes are powers of two from 512 through 4096 bytes; smaller supplied values
  retain the default of 512 bytes. Invalid geometry returns an error.
- `image::Volume`: enumerate files, read standard-information timestamps and serve
  arbitrary-offset resident, fragmented, sparse and compressed content.
- `image_mount::new_session`: construct a read-only FUSE session.
- `image_mount::mount`: start a background mount, returned as `Mounted`.
- `image_mount::mount_image`: the same for an `Image` opened with `from_disk`.
- `Mounted::unmount`: unmount and join the worker threads; dropping it also unmounts.
- `image_mount::unmount_on_interrupt`: opt in to a process-wide signal handler.

FUSE 3 and `/dev/fuse` are required for mounting. Do not install multiple process-wide
interrupt handlers. Mount creation and registration are synchronized with the handler;
registered handles remain usable after the worker starts. `Mounted::unmount` also works
when a callback has already detached the image. The CLI and orchestration remain in Juntei.

The VHDX reader is the workspace's `ys-vhdx-parser`; `ntfs-core`, `fuser` and `ctrlc`
provide NTFS decoding, the FUSE protocol and signal delivery respectively. Source
images are opened read-only and writes through the mount are refused.
