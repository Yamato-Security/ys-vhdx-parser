# ys-vhdx-parser

Yamato Security's VHDX reader and read-only NTFS/FUSE mounting libraries, used by
[Juntei](https://github.com/Yamato-Security/juntei).

Both crates are version 1.0.0 and use Rust edition 2024. Building the workspace
requires Rust 1.88 or newer.

| Crate | Rust library | Purpose | License |
|---|---|---|---|
| [`ys-vhdx-parser`](core/) | `vhdx` | VHDX container decoding and a `Read + Seek` virtual disk | Apache-2.0 |
| [`ys-vhdx-mount`](mount/) | `ys_vhdx_mount` | NTFS volumes, file reads and read-only FUSE mounting | RPL-1.5 OR AGPL-3.0-only |

The reader is based on Security Ronin's `vhdx-core` 0.4.1, at commit
`40358d3153c121dcea986a125fa6a8f88853bc1e`, retaining its regression tests and
attribution. The mounting layer is moved from Juntei PR #135, including its regression
fixes and public KAPE-layout fixture. See [NOTICE](NOTICE) for attribution and the
component licenses.

## VHDX reader

The container reader works across platforms, without mounting or privileged access.
It supports dynamic and fixed VHDX, explicit parent readers for differencing images,
and dirty-log replay in memory. It does not write to the evidence image.

```toml
[dependencies]
vhdx = { package = "ys-vhdx-parser", git = "https://github.com/Yamato-Security/ys-vhdx-parser", branch = "main" }
```

```rust
use std::io::Read;
use vhdx::VhdxReader;

let mut disk = VhdxReader::open("disk.vhdx")?;
let mut sector = vec![0; disk.logical_sector_size() as usize];
disk.read_exact(&mut sector)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Native NTFS reads on Linux, macOS, and Windows

The `image` API opens NTFS volumes and file streams directly, without a mounting driver,
FUSE, administrator privileges, or temporary extraction. Add the dependency on every
platform:

```toml
[dependencies]
ys_vhdx_mount = { package = "ys-vhdx-mount", git = "https://github.com/Yamato-Security/ys-vhdx-parser", branch = "main" }
```

For a `Security.evtx` at the volume root (use `Volume::lookup` to traverse directories):

```rust
use std::io::Read;
use std::sync::Arc;
use ys_vhdx_mount::image::{Image, ROOT_RECORD};

let image = Arc::new(Image::open("disk.vhdx")?);
let entry = image.volumes[0].lookup(ROOT_RECORD, "Security.evtx")?
    .ok_or("Security.evtx not found")?;
let mut file = image.file_reader(0, entry.record)?;
let mut signature = [0; 8];
file.read_exact(&mut signature)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The stream implements `Read + Seek`, retains the image while open, and has an independent
position. Opening it does not load the file contents; reads use the existing NTFS
resident, fragmented, sparse, and compressed-data handling.

## Read-only mounting

`ys-vhdx-mount` provides `image::Image` and `image_mount` APIs. The former works on Linux, macOS, and Windows, and discovers
MBR/GPT NTFS volumes and reads resident, fragmented, sparse and compressed streams;
`Image::file_reader` provides streaming `Read + Seek` access without mounting or extracting.
The mounting API serves them through FUSE on Linux and exposes explicit unmount handles. Besides VHDX
files (`Image::open`), `Image::from_disk` takes the disk of any other container that the
caller reads (an E01 image, for example) and `image_mount::mount_image` mounts it.

```toml
[target.'cfg(target_os = "linux")'.dependencies]
vhdx_mount = { package = "ys-vhdx-mount", git = "https://github.com/Yamato-Security/ys-vhdx-parser", branch = "main" }
```

Mounting requires Linux, access to `/dev/fuse`, and FUSE 3's `fusermount3` helper.
The crate does not require libfuse at build time. The image and the FUSE view are
read-only. Multiple NTFS volumes appear as `Volume1`, `Volume2`, and so on.
Unreadable NTFS volumes are retained in `Image::problems` for callers to report.

For the command-line interface, use Juntei:

```bash
mkdir mounted
juntei mount collection.vhdx mounted
juntei auto-parse -d collections --vhdx -o parsed
```

The mounting view uses exact stored names and standard-information timestamps.
DOS aliases and alternate data streams are not exposed. EFS content is unreadable.
Compressed content is materialized only on read, up to 1 GiB per file. The content
cache normally retains at most 64 MiB; a larger accepted file occupies it alone.
Callers should arrange unmounting on normal completion and interruption; Juntei
provides that lifecycle around these APIs.

## Validation

```bash
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
```

Reader tests include public dynamic, fixed and differencing images, synthetic log
replay and malformed-input tests. Optional external-corpus/QEMU tests retain their
original availability gates. Mount tests include known SHA-256 checks for the
KAPE-layout files, sparse/fragmented/compressed data, malformed partition tables,
partial volumes and FILETIME precision. Linux CI requires the live FUSE test;
Juntei also tests its CLI, automatic parsing and interrupt cleanup against this SDK.
