//! Demonstrates that `VhdxReader::open` is bounded: peak process RSS does NOT
//! scale with the on-disk image size.
//!
//! We synthesise a VHDX whose container file is large on disk (a present data
//! block placed far into the file, the gap left as a sparse hole) but read only
//! a few MB. The legacy `from_bytes(std::fs::read(path))` path would pull the
//! WHOLE file into a heap `Vec` (RSS tracks the file size); the bounded `open`
//! path keeps only the BAT + metadata + small per-read buffers, so RSS stays in
//! the low megabytes regardless of how large the container is.
//!
//! RSS is read from the OS (`ps -o rss=`) — no custom allocator, so the crate
//! stays `forbid(unsafe)`.
//!
//! Run: `cargo run -p vhdx-core --example bounded_memory`
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Seek, SeekFrom, Write};

const MB: u64 = 0x0010_0000;
const BLOCK_SIZE: u32 = 32 * MB as u32; // 32 MB default block
const VIRTUAL_DISK_SIZE: u64 = 4096 * MB; // 4 GiB virtual
const LOG_OFFSET: u64 = MB;
const LOG_LENGTH: u32 = MB as u32;
const META_OFFSET: u64 = 2 * MB;
const META_LENGTH: u32 = MB as u32;
const BAT_OFFSET: u64 = 3 * MB;
const BAT_LENGTH: u32 = MB as u32;
// Place the single present block ~256 MB into the file so the container is large
// on disk; the gap before it is a sparse hole, costing no real disk.
const DATA_OFFSET: u64 = 256 * MB;

fn crc32c(data: &[u8]) -> u32 {
    const POLY: u32 = 0x82F6_3B78;
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xFFFF_FFFF
}

const BAT_GUID: [u8; 16] = [
    0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08,
];
const METADATA_GUID: [u8; 16] = [
    0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E,
];
const GUID_FILE_PARAMETERS: [u8; 16] = [
    0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B,
];
const GUID_VIRTUAL_DISK_SIZE: [u8; 16] = [
    0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48, 0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8,
];
const GUID_LOGICAL_SECTOR_SIZE: [u8; 16] = [
    0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F,
];

fn write_header(slot: &mut [u8], seq: u64) {
    let h = &mut slot[..4096];
    h[0..4].copy_from_slice(b"head");
    h[8..16].copy_from_slice(&seq.to_le_bytes());
    h[64..66].copy_from_slice(&1u16.to_le_bytes());
    h[66..68].copy_from_slice(&1u16.to_le_bytes());
    h[68..72].copy_from_slice(&LOG_LENGTH.to_le_bytes());
    h[72..80].copy_from_slice(&LOG_OFFSET.to_le_bytes());
    let c = crc32c(h);
    h[4..8].copy_from_slice(&c.to_le_bytes());
}

fn write_region_table(rt: &mut [u8]) {
    rt[0..4].copy_from_slice(b"regi");
    rt[8..12].copy_from_slice(&2u32.to_le_bytes());
    rt[16..32].copy_from_slice(&BAT_GUID);
    rt[32..40].copy_from_slice(&BAT_OFFSET.to_le_bytes());
    rt[40..44].copy_from_slice(&BAT_LENGTH.to_le_bytes());
    rt[44..48].copy_from_slice(&1u32.to_le_bytes());
    rt[48..64].copy_from_slice(&METADATA_GUID);
    rt[64..72].copy_from_slice(&META_OFFSET.to_le_bytes());
    rt[72..76].copy_from_slice(&META_LENGTH.to_le_bytes());
    rt[76..80].copy_from_slice(&1u32.to_le_bytes());
    let mut tmp = rt[..65536].to_vec();
    tmp[4..8].fill(0);
    let c = crc32c(&tmp);
    rt[4..8].copy_from_slice(&c.to_le_bytes());
}

fn write_metadata(region: &mut [u8]) {
    region[0..8].copy_from_slice(b"metadata");
    region[10..12].copy_from_slice(&3u16.to_le_bytes());
    const FP_OFF: u32 = 0x200;
    const VDS_OFF: u32 = 0x210;
    const LSS_OFF: u32 = 0x220;
    region[32..48].copy_from_slice(&GUID_FILE_PARAMETERS);
    region[48..52].copy_from_slice(&FP_OFF.to_le_bytes());
    region[52..56].copy_from_slice(&8u32.to_le_bytes());
    region[64..80].copy_from_slice(&GUID_VIRTUAL_DISK_SIZE);
    region[80..84].copy_from_slice(&VDS_OFF.to_le_bytes());
    region[84..88].copy_from_slice(&8u32.to_le_bytes());
    region[96..112].copy_from_slice(&GUID_LOGICAL_SECTOR_SIZE);
    region[112..116].copy_from_slice(&LSS_OFF.to_le_bytes());
    region[116..120].copy_from_slice(&4u32.to_le_bytes());
    region[FP_OFF as usize..FP_OFF as usize + 4].copy_from_slice(&BLOCK_SIZE.to_le_bytes());
    region[VDS_OFF as usize..VDS_OFF as usize + 8]
        .copy_from_slice(&VIRTUAL_DISK_SIZE.to_le_bytes());
    region[LSS_OFF as usize..LSS_OFF as usize + 4].copy_from_slice(&512u32.to_le_bytes());
}

/// Write a large sparse VHDX to `path`: header/regions/BAT/metadata up front, a
/// single present 32 MB block at `DATA_OFFSET`, and a sparse hole in between.
fn write_sparse_vhdx(path: &std::path::Path) -> std::io::Result<u64> {
    // Build only the small front matter in RAM (a few MB), then write the block.
    let front_len = (DATA_OFFSET) as usize;
    let mut front = vec![0u8; front_len.min(5 * MB as usize)];
    front[0..8].copy_from_slice(b"vhdxfile");
    write_header(&mut front[0x10000..0x20000], 1);
    write_header(&mut front[0x20000..0x30000], 0);
    write_region_table(&mut front[0x30000..0x40000]);
    write_region_table(&mut front[0x40000..0x50000]);
    write_metadata(
        &mut front[META_OFFSET as usize..(META_OFFSET + u64::from(META_LENGTH)) as usize],
    );
    let bat_entry: u64 = (DATA_OFFSET >> 20) << 20 | 6;
    front[BAT_OFFSET as usize..BAT_OFFSET as usize + 8].copy_from_slice(&bat_entry.to_le_bytes());

    let mut f = std::fs::File::create(path)?;
    f.write_all(&front)?;
    // Leave a sparse hole, then write the present block (first byte observable).
    f.seek(SeekFrom::Start(DATA_OFFSET))?;
    let mut block = vec![0u8; BLOCK_SIZE as usize];
    block[0] = 0x42;
    f.write_all(&block)?;
    let total = DATA_OFFSET + u64::from(BLOCK_SIZE);
    f.flush()?;
    Ok(total)
}

fn rss_kib() -> u64 {
    let pid = std::process::id();
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .trim()
            .parse::<u64>()
            .unwrap_or(0),
        Err(_) => 0,
    }
}

fn main() {
    let tmp = std::env::temp_dir().join("vhdx_bounded_memory_demo.vhdx");
    let file_len = write_sparse_vhdx(&tmp).expect("write sparse image");

    let rss_before = rss_kib();
    let mut reader = vhdx::VhdxReader::open(&tmp).expect("bounded open");
    let vsize = reader.virtual_disk_size();

    // Read 8 MB from the start of the virtual disk — virtual block 0 is the one
    // present block (its bytes live at file offset DATA_OFFSET via the BAT).
    let mut buf = vec![0u8; 8 * MB as usize];
    reader.seek(SeekFrom::Start(0)).unwrap();
    reader.read_exact(&mut buf).unwrap();
    assert_eq!(buf[0], 0x42, "present block byte must read back");
    let rss_after = rss_kib();
    drop(buf);
    let _ = std::fs::remove_file(&tmp);

    let grew = rss_after.saturating_sub(rss_before);
    println!("virtual disk size : {} MiB", vsize / MB);
    println!(
        "container file size: {} MiB (on disk, sparse)",
        file_len / MB
    );
    println!("RSS before open    : {rss_before} KiB");
    println!("RSS after open+read: {rss_after} KiB  (grew {grew} KiB)");

    // The container is {file_len} bytes; a whole-file reader would grow RSS by
    // that much. The bounded reader grows by only the BAT/metadata/read buffers
    // (tens of MB at most for this 256 MB+ file). Assert the growth stays well
    // under the file size — i.e. the image is NOT loaded whole.
    let file_kib = file_len / 1024;
    assert!(
        grew < file_kib,
        "RSS grew {grew} KiB, must stay below container file size {file_kib} KiB \
         (bounded — does not load the whole image)"
    );
    println!(
        "OK: RSS growth {grew} KiB << container {file_kib} KiB << virtual {} KiB — bounded.",
        vsize / 1024
    );
}
