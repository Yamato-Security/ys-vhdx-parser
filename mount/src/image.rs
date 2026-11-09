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

//! Read-only access to the NTFS volumes of a disk image: a VHDX (a triage collection's or a Hyper-V
//! disk), read with this repository's VHDX reader (dynamic, fixed and differencing disks, a
//! pending log replayed in memory), or the disk of any other container a caller reads
//! ([`Image::from_disk`]), such as an E01 image. The volumes are found from the MBR or GPT (or the
//! whole disk is one volume), and each NTFS volume's directories and files are read with
//! ntfs-core, which also accepts the boot sectors that DiscUtils writes (jump instruction and
//! `55 AA` signature zeroed). Nothing is written to the image: `juntei mount` and `auto-parse`
//! serve these files through FUSE.

use ntfs_core::{AttributeBody, Filetime, MftRecordHeader, NtfsFs, Run, StandardInformation};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// The record of a volume's root directory.
pub const ROOT_RECORD: u64 = 5;

const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
const ATTR_DATA: u32 = 0x80;
const RECORD_IN_USE: u16 = 0x0001;
const RECORD_DIRECTORY: u16 = 0x0002;
/// `$FILE_NAME` flag of a directory (an index is present).
const NAME_DIRECTORY: u32 = 0x1000_0000;
/// `$FILE_NAME` namespace of a DOS 8.3 alias, listed beside the long name.
const NAMESPACE_DOS: u8 = 2;
/// Attribute flag of an EFS-encrypted value.
const ATTR_ENCRYPTED: u16 = 0x4000;
/// A compressed stream is decompressed whole: larger ones are refused.
const MAX_DECOMPRESSED: u64 = 1 << 30;
/// File layouts kept for repeated reads of the same files.
const LAYOUT_CACHE: usize = 4096;
/// Keep ordinary compressed reads warm without retaining thousands of decompressed files.
/// A single larger file may occupy the cache alone, up to MAX_DECOMPRESSED.
const COMPRESSED_CACHE_BYTES: u64 = 64 << 20;

/// The bytes of a disk, from whatever container holds them: what [`Image::from_disk`] takes.
pub trait DiskReader: Read + Seek + Send {}

impl<T: Read + Seek + Send> DiskReader for T {}

/// The disk of an image, shared by its volumes.
type Disk = Arc<Mutex<Box<dyn DiskReader>>>;

/// `len` bytes of the disk from `start`: one volume.
struct Window {
    disk: Disk,
    start: u64,
    len: u64,
    pos: u64,
}

impl Window {
    fn new(disk: Disk, start: u64, len: u64) -> Self {
        Window {
            disk,
            start,
            len,
            pos: 0,
        }
    }
}

impl Read for Window {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = usize::try_from(self.len.saturating_sub(self.pos))
            .unwrap_or(usize::MAX)
            .min(buf.len());
        if n == 0 {
            return Ok(0);
        }
        let mut disk = self
            .disk
            .lock()
            .map_err(|_| io::Error::other("disk lock poisoned"))?;
        disk.seek(SeekFrom::Start(self.start + self.pos))?;
        let read = disk.read(&mut buf[..n])?;
        self.pos += read as u64;
        Ok(read)
    }
}

impl Seek for Window {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let pos = match to {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = pos.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad seek"))?;
        Ok(self.pos)
    }
}

/// A disk image and the NTFS volumes found in it.
pub struct Image {
    /// The virtual disk's size in bytes.
    pub size: u64,
    pub volumes: Vec<Volume>,
    /// Unreadable NTFS partitions must remain visible even when another volume opens.
    pub problems: Vec<String>,
}

impl Image {
    /// Open a VHDX file and every NTFS volume in it.
    ///
    /// # Errors
    /// When the file isn't a readable VHDX, or holds no NTFS volume.
    pub fn open(path: &Path) -> io::Result<Image> {
        let reader = vhdx::VhdxReader::open(path)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let size = reader.virtual_disk_size();
        let sector = u64::from(reader.logical_sector_size());
        Image::from_disk(Box::new(reader), size, sector)
    }

    /// Every NTFS volume of a disk of `size` bytes with sectors of `sector_size` bytes (512 if
    /// smaller), whatever container holds it: its bytes are read from `disk`, which is never
    /// written to.
    ///
    /// # Errors
    /// When the disk can't be read, or holds no NTFS volume.
    pub fn from_disk(disk: Box<dyn DiskReader>, size: u64, sector_size: u64) -> io::Result<Image> {
        let sector = sector_size.max(512);
        let disk: Disk = Arc::new(Mutex::new(disk));
        let mut volumes = Vec::new();
        let mut problems = Vec::new();
        for (index, (start, len)) in ntfs_partitions(&disk, size, sector)?
            .into_iter()
            .enumerate()
        {
            match Volume::open(disk.clone(), start, len) {
                Ok(volume) => volumes.push(volume),
                Err(e) => problems.push(format!("volume {} at byte {start}: {e}", index + 1)),
            }
        }
        if volumes.is_empty() {
            let why = if problems.is_empty() {
                "no NTFS volume found".to_string()
            } else {
                problems.join("; ")
            };
            return Err(io::Error::new(io::ErrorKind::InvalidData, why));
        }
        Ok(Image {
            size,
            volumes,
            problems,
        })
    }
}

/// A directory entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub record: u64,
    pub directory: bool,
}

/// What a file or directory's record says about it.
#[derive(Clone, Copy, Debug)]
pub struct Stat {
    pub directory: bool,
    /// The size of a file's unnamed `$DATA` stream; 0 for a directory.
    pub size: u64,
    /// `$STANDARD_INFORMATION` times.
    pub created: Filetime,
    pub modified: Filetime,
    pub changed: Filetime,
    pub accessed: Filetime,
}

/// Where a file's content is.
enum Layout {
    /// No unnamed `$DATA` stream.
    Empty,
    /// In the record.
    Resident(Vec<u8>),
    /// In clusters: the runs in order (`None` for a sparse run), the stream's size, and how much
    /// of it is initialized (the rest reads as zeros).
    Runs {
        runs: Vec<Run>,
        size: u64,
        initialized: u64,
    },
    /// Compressed data is materialized only when read, never for getattr/stat.
    Compressed { size: u64, initialized: u64 },
    /// Content that can't be read (EFS-encrypted, or compressed and too large), and its size.
    Unreadable(u64, &'static str),
}

impl Layout {
    fn size(&self) -> u64 {
        match self {
            Layout::Empty => 0,
            Layout::Resident(bytes) => bytes.len() as u64,
            Layout::Runs { size, .. }
            | Layout::Compressed { size, .. }
            | Layout::Unreadable(size, _) => *size,
        }
    }
}

#[derive(Default)]
struct CompressedCache {
    files: HashMap<u64, Arc<Vec<u8>>>,
    bytes: u64,
}

/// One NTFS volume of an image.
pub struct Volume {
    /// Where it starts on the disk, in bytes.
    pub start: u64,
    /// Its length in bytes.
    pub len: u64,
    fs: NtfsFs<Window>,
    /// For reading file content (the file system keeps its own reader for records).
    data: Mutex<Window>,
    cluster_size: u64,
    layouts: Mutex<HashMap<u64, Arc<Layout>>>,
    directories: Mutex<HashMap<u64, Arc<Vec<Entry>>>>,
    compressed: Mutex<CompressedCache>,
}

impl Volume {
    fn open(disk: Disk, start: u64, len: u64) -> io::Result<Volume> {
        let fs = NtfsFs::open(Window::new(disk.clone(), start, len)).map_err(other)?;
        let cluster_size = fs.boot().cluster_size();
        Ok(Volume {
            start,
            len,
            fs,
            data: Mutex::new(Window::new(disk, start, len)),
            cluster_size,
            layouts: Mutex::new(HashMap::new()),
            directories: Mutex::new(HashMap::new()),
            compressed: Mutex::new(CompressedCache::default()),
        })
    }

    /// The entries of directory `record`: long names only (not the DOS 8.3 aliases), without `.`.
    ///
    /// # Errors
    /// When the record can't be read or isn't a directory.
    pub fn list(&self, record: u64) -> io::Result<Arc<Vec<Entry>>> {
        if let Some(entries) = lock(&self.directories)?.get(&record) {
            return Ok(entries.clone());
        }
        let bytes = self.fs.read_record(record).map_err(other)?;
        let mut entries: Vec<Entry> = self
            .fs
            .directory_entries(&bytes)
            .map_err(other)?
            .into_iter()
            .filter_map(|entry| {
                let name = entry.file_name?;
                (name.namespace != NAMESPACE_DOS && name.name != "." && !name.name.is_empty())
                    .then_some(Entry {
                        directory: name.flags & NAME_DIRECTORY != 0,
                        record: entry.file_reference.record_number,
                        name: name.name,
                    })
            })
            .collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries.dedup_by(|a, b| a.name == b.name);
        let entries = Arc::new(entries);
        lock(&self.directories)?.insert(record, entries.clone());
        Ok(entries)
    }

    /// The entry of directory `record` named `name` exactly.
    ///
    /// # Errors
    /// As [`Volume::list`].
    pub fn lookup(&self, record: u64, name: &str) -> io::Result<Option<Entry>> {
        let entries = self.list(record)?;
        Ok(entries
            .binary_search_by(|e| e.name.as_str().cmp(name))
            .ok()
            .map(|at| entries[at].clone()))
    }

    /// What record `record` says about its file or directory.
    ///
    /// # Errors
    /// When the record can't be read or isn't in use.
    pub fn stat(&self, record: u64) -> io::Result<Stat> {
        let bytes = self.fs.read_record(record).map_err(other)?;
        let header = MftRecordHeader::parse(&bytes).map_err(other)?;
        if header.flags & RECORD_IN_USE == 0 {
            return Err(io::Error::new(io::ErrorKind::NotFound, "record not in use"));
        }
        let directory = header.flags & RECORD_DIRECTORY != 0;
        let attributes =
            ntfs_core::parse_attributes(&bytes, usize::from(header.first_attribute_offset))
                .map_err(other)?;
        let times = attributes
            .iter()
            .find(|a| a.type_code == ATTR_STANDARD_INFORMATION)
            .and_then(|a| a.resident_content(&bytes))
            .and_then(|content| StandardInformation::parse(content).ok());
        let zero = Filetime(0);
        let size = if directory {
            0
        } else {
            self.layout(record)?.size()
        };
        Ok(Stat {
            directory,
            size,
            created: times.as_ref().map_or(zero, |t| t.created),
            modified: times.as_ref().map_or(zero, |t| t.modified),
            changed: times.as_ref().map_or(zero, |t| t.mft_modified),
            accessed: times.as_ref().map_or(zero, |t| t.accessed),
        })
    }

    /// Up to `len` bytes of file `record`'s content from `offset`; fewer at its end.
    ///
    /// # Errors
    /// When the content can't be read.
    pub fn read(&self, record: u64, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let layout = self.layout(record)?;
        let size = layout.size();
        let end = offset.saturating_add(len as u64).min(size);
        if offset >= end {
            return Ok(Vec::new());
        }
        let (from, to) = (offset as usize, end as usize);
        match &*layout {
            Layout::Empty => Ok(Vec::new()),
            Layout::Resident(bytes) => Ok(bytes[from..to].to_vec()),
            Layout::Compressed { size, initialized } => {
                let bytes = self.compressed_content(record, *size, *initialized)?;
                Ok(bytes[from..to].to_vec())
            }
            Layout::Unreadable(_, why) => Err(io::Error::other(*why)),
            Layout::Runs {
                runs, initialized, ..
            } => {
                let mut out = vec![0u8; to - from];
                let mut data = lock(&self.data)?;
                read_runs(&mut *data, runs, self.cluster_size, offset, &mut out)?;
                // past the initialized size the stream reads as zeros, whatever its clusters hold
                if *initialized < end {
                    let zero_from = (initialized.saturating_sub(offset) as usize).min(out.len());
                    out[zero_from..].fill(0);
                }
                Ok(out)
            }
        }
    }

    fn compressed_content(
        &self,
        record: u64,
        size: u64,
        initialized: u64,
    ) -> io::Result<Arc<Vec<u8>>> {
        let mut cache = lock(&self.compressed)?;
        if let Some(bytes) = cache.files.get(&record) {
            return Ok(bytes.clone());
        }
        if cache.files.len() >= LAYOUT_CACHE
            || cache.bytes.saturating_add(size) > COMPRESSED_CACHE_BYTES
        {
            cache.files.clear();
            cache.bytes = 0;
        }
        // Serialize materialization: concurrent reads of one large file must not each
        // allocate a separate decompressed copy.
        let mut bytes = self
            .fs
            .read_data_by_record(record, None, size)
            .map_err(other)?;
        if bytes.len() as u64 != size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "compressed stream is shorter than its size",
            ));
        }
        bytes[initialized.min(size) as usize..].fill(0);
        let bytes = Arc::new(bytes);
        cache.bytes += size;
        cache.files.insert(record, bytes.clone());
        Ok(bytes)
    }

    /// Where file `record`'s content is, from its records (an attribute list's included).
    fn layout(&self, record: u64) -> io::Result<Arc<Layout>> {
        if let Some(layout) = lock(&self.layouts)?.get(&record) {
            return Ok(layout.clone());
        }
        let layout = Arc::new(self.read_layout(record)?);
        let mut layouts = lock(&self.layouts)?;
        if layouts.len() >= LAYOUT_CACHE {
            layouts.clear();
        }
        layouts.insert(record, layout.clone());
        Ok(layout)
    }

    fn read_layout(&self, record: u64) -> io::Result<Layout> {
        let records = self.records(record)?;
        // the first piece of the unnamed $DATA stream: resident, or non-resident from VCN 0
        let mut first = None;
        for bytes in &records {
            let header = MftRecordHeader::parse(bytes).map_err(other)?;
            let attributes =
                ntfs_core::parse_attributes(bytes, usize::from(header.first_attribute_offset))
                    .map_err(other)?;
            for attribute in attributes {
                if attribute.type_code != ATTR_DATA || attribute.name.is_some() {
                    continue;
                }
                let starts = match attribute.body {
                    AttributeBody::Resident { .. } => true,
                    AttributeBody::NonResident { start_vcn, .. } => start_vcn == 0,
                };
                if starts {
                    first = Some((bytes, attribute));
                    break;
                }
            }
            if first.is_some() {
                break;
            }
        }
        let Some((bytes, attribute)) = first else {
            return Ok(Layout::Empty);
        };
        Ok(match attribute.body {
            AttributeBody::Resident { .. } => Layout::Resident(
                attribute
                    .resident_content(bytes)
                    .ok_or_else(|| io::Error::other("resident content out of bounds"))?
                    .to_vec(),
            ),
            AttributeBody::NonResident {
                real_size,
                initialized_size,
                ..
            } => {
                if attribute.flags & ATTR_ENCRYPTED != 0 {
                    Layout::Unreadable(real_size, "EFS-encrypted content")
                } else if attribute.is_compressed() {
                    if real_size > MAX_DECOMPRESSED {
                        Layout::Unreadable(real_size, "compressed content too large to read")
                    } else {
                        Layout::Compressed {
                            size: real_size,
                            initialized: initialized_size.min(real_size),
                        }
                    }
                } else {
                    Layout::Runs {
                        runs: self.fs.runs_by_record(record, None).map_err(other)?,
                        size: real_size,
                        initialized: initialized_size.min(real_size),
                    }
                }
            }
        })
    }

    /// Record `record` and, when it has an attribute list, the other records it names.
    fn records(&self, record: u64) -> io::Result<Vec<Vec<u8>>> {
        let base = self.fs.read_record(record).map_err(other)?;
        let header = MftRecordHeader::parse(&base).map_err(other)?;
        let attributes =
            ntfs_core::parse_attributes(&base, usize::from(header.first_attribute_offset))
                .map_err(other)?;
        let mut records = Vec::new();
        if let Some(list) = attributes
            .iter()
            .find(|a| a.type_code == ATTR_ATTRIBUTE_LIST)
        {
            let content = {
                let mut data = lock(&self.data)?;
                ntfs_core::read_attribute_value(&mut *data, &base, list, self.cluster_size)
                    .map_err(other)?
            };
            let mut seen = std::collections::BTreeSet::from([record]);
            for entry in ntfs_core::parse_attribute_list(&content).map_err(other)? {
                let number = entry.base_reference.record_number;
                if seen.insert(number) {
                    records.push(self.fs.read_record(number).map_err(other)?);
                }
            }
        }
        records.insert(0, base);
        Ok(records)
    }
}

/// Fill `out` with the stream bytes from `offset`, mapped through `runs`; sparse runs are zeros.
fn read_runs<R: Read + Seek>(
    volume: &mut R,
    runs: &[Run],
    cluster_size: u64,
    offset: u64,
    out: &mut [u8],
) -> io::Result<()> {
    let end = offset + out.len() as u64;
    let mut run_start = 0u64;
    for run in runs {
        let run_len = run
            .length
            .checked_mul(cluster_size)
            .ok_or_else(|| io::Error::other("run length overflows"))?;
        let run_end = run_start.saturating_add(run_len);
        let from = offset.max(run_start);
        let to = end.min(run_end);
        if from < to {
            let target = &mut out[(from - offset) as usize..(to - offset) as usize];
            match run.lcn {
                Some(lcn) => {
                    let at = lcn
                        .checked_mul(cluster_size)
                        .and_then(|b| b.checked_add(from - run_start))
                        .ok_or_else(|| io::Error::other("cluster offset overflows"))?;
                    volume.seek(SeekFrom::Start(at))?;
                    volume.read_exact(target)?;
                }
                None => target.fill(0),
            }
        }
        if run_end >= end {
            return Ok(());
        }
        run_start = run_end;
    }
    // the runs end before the stream does: the rest is missing
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "the stream's runs end before its size",
    ))
}

/// The NTFS volumes of a disk, as (start, length) in bytes: the partitions of its MBR (extended
/// partitions included) or GPT whose boot sector names NTFS, or the whole disk when it is one
/// volume.
fn ntfs_partitions(disk: &Disk, size: u64, sector: u64) -> io::Result<Vec<(u64, u64)>> {
    let mut reader = Window::new(disk.clone(), 0, size);
    let first = read_at(&mut reader, 0, 512)?;
    let is_ntfs = |reader: &mut Window, start: u64| -> bool {
        read_at(reader, start + 3, 8).is_ok_and(|oem| oem == b"NTFS    ")
    };
    if first.get(3..11) == Some(b"NTFS    ") {
        return Ok(vec![(0, size)]);
    }
    let mut candidates = Vec::new();
    if first.get(510..512) == Some(&[0x55, 0xAA]) {
        let entries = mbr_entries(&first);
        if entries.iter().any(|e| e.0 == 0xEE) {
            candidates.extend(gpt_partitions(&mut reader, sector)?);
        } else {
            for &(kind, lba, sectors) in &entries {
                if matches!(kind, 0x05 | 0x0F | 0x85) {
                    candidates.extend(extended_partitions(&mut reader, lba, sector)?);
                } else if kind != 0 {
                    candidates.push((lba * sector, sectors * sector));
                }
            }
        }
    }
    Ok(candidates
        .into_iter()
        .filter(|&(start, len)| len > 0 && start < size)
        .map(|(start, len)| (start, len.min(size - start)))
        .filter(|&(start, _)| is_ntfs(&mut reader, start))
        .collect())
}

/// The four primary entries of an MBR: (type, first LBA, sectors).
fn mbr_entries(mbr: &[u8]) -> Vec<(u8, u64, u64)> {
    (0..4)
        .map(|i| {
            let e = &mbr[446 + 16 * i..446 + 16 * (i + 1)];
            (
                e[4],
                u64::from(u32::from_le_bytes([e[8], e[9], e[10], e[11]])),
                u64::from(u32::from_le_bytes([e[12], e[13], e[14], e[15]])),
            )
        })
        .collect()
}

/// The logical partitions of the extended partition at LBA `base`, following its chain of EBRs
/// (at most 128).
fn extended_partitions<R: Read + Seek>(
    reader: &mut R,
    base: u64,
    sector: u64,
) -> io::Result<Vec<(u64, u64)>> {
    let mut out = Vec::new();
    let mut ebr = base;
    let mut visited = HashSet::new();
    for _ in 0..128 {
        if !visited.insert(ebr) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cyclic extended partition chain",
            ));
        }
        let Ok(bytes) = read_at(reader, ebr * sector, 512) else {
            return Ok(out);
        };
        if bytes.get(510..512) != Some(&[0x55, 0xAA]) {
            return Ok(out);
        }
        let entries = mbr_entries(&bytes);
        let (kind, lba, sectors) = entries[0];
        if kind != 0 {
            out.push(((ebr + lba) * sector, sectors * sector));
        }
        let (next_kind, next_lba, _) = entries[1];
        if next_kind == 0 || next_lba == 0 {
            return Ok(out);
        }
        ebr = base + next_lba;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "extended partition chain exceeds 128 entries",
    ))
}

/// The partitions of a GPT: (start, length) in bytes.
fn gpt_partitions<R: Read + Seek>(reader: &mut R, sector: u64) -> io::Result<Vec<(u64, u64)>> {
    let header = read_at(reader, sector, 92)?;
    if header.get(..8) != Some(b"EFI PART") {
        return Ok(Vec::new());
    }
    let u64_at = |at: usize| u64::from_le_bytes(header[at..at + 8].try_into().unwrap_or_default());
    let u32_at = |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().unwrap_or_default());
    let (table, count, entry_size) = (u64_at(72), u32_at(80).min(1024), u64::from(u32_at(84)));
    if !(128..=4096).contains(&entry_size) {
        return Ok(Vec::new());
    }
    let table_offset = table
        .checked_mul(sector)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "GPT table offset overflows"))?;
    let mut out = Vec::new();
    for i in 0..u64::from(count) {
        let offset = i
            .checked_mul(entry_size)
            .and_then(|n| table_offset.checked_add(n))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "GPT entry offset overflows")
            })?;
        let Ok(entry) = read_at(reader, offset, 128) else {
            break;
        };
        if entry[..16].iter().all(|&b| b == 0) {
            continue;
        }
        let first = u64::from_le_bytes(entry[32..40].try_into().unwrap_or_default());
        let last = u64::from_le_bytes(entry[40..48].try_into().unwrap_or_default());
        if last >= first {
            let start = first.checked_mul(sector).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "GPT partition offset overflows")
            })?;
            let len = (last - first)
                .checked_add(1)
                .and_then(|n| n.checked_mul(sector))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "GPT partition length overflows")
                })?;
            out.push((start, len));
        }
    }
    Ok(out)
}

fn read_at<R: Read + Seek>(reader: &mut R, at: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    reader.seek(SeekFrom::Start(at))?;
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn other(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

fn lock<T>(mutex: &Mutex<T>) -> io::Result<std::sync::MutexGuard<'_, T>> {
    mutex.lock().map_err(|_| io::Error::other("lock poisoned"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_map_offsets_to_clusters_and_sparse_runs_to_zeros() {
        // a 4-cluster volume of 4-byte clusters: cluster n holds bytes n*4 .. n*4+4
        let volume: Vec<u8> = (0u8..16).collect();
        let runs = [
            Run {
                length: 1,
                lcn: Some(2),
            },
            Run {
                length: 1,
                lcn: None,
            },
            Run {
                length: 2,
                lcn: Some(0),
            },
        ];
        let mut out = vec![0xFFu8; 16];
        read_runs(&mut io::Cursor::new(&volume), &runs, 4, 0, &mut out).unwrap();
        assert_eq!(out, [8, 9, 10, 11, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7]);
        let mut out = vec![0u8; 6];
        read_runs(&mut io::Cursor::new(&volume), &runs, 4, 2, &mut out).unwrap();
        assert_eq!(out, [10, 11, 0, 0, 0, 0]);
        // past the last run
        let mut out = vec![0u8; 4];
        assert!(read_runs(&mut io::Cursor::new(&volume), &runs, 4, 14, &mut out).is_err());
    }

    /// The sample KAPE VHDX, decompressed into a new directory.
    fn kape_sample() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kape-sample.vhdx");
        let gz = std::fs::File::open(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("test_files/vhdx/kape-sample.vhdx.gz"),
        )
        .unwrap();
        let mut out = std::fs::File::create(&path).unwrap();
        io::copy(&mut flate2::read::GzDecoder::new(gz), &mut out).unwrap();
        (dir, path)
    }

    /// Change logical bytes in a private copy of the bundled fixture. Its BAT is at 3 MiB
    /// and its fully present payload blocks are 1 MiB (see make_kape_sample.py).
    fn patch_sample(path: &Path, offset: u64, replacement: &[u8]) {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let block = offset / (1 << 20);
        file.seek(SeekFrom::Start((3 << 20) + block * 8)).unwrap();
        let mut entry = [0; 8];
        file.read_exact(&mut entry).unwrap();
        let entry = u64::from_le_bytes(entry);
        assert_eq!(entry & 7, 6);
        let physical = (entry & !((1 << 20) - 1)) + offset % (1 << 20);
        assert!(offset % (1 << 20) + replacement.len() as u64 <= 1 << 20);
        file.seek(SeekFrom::Start(physical)).unwrap();
        file.write_all(replacement).unwrap();
    }

    #[test]
    fn compressed_file_metadata_survives_damaged_content() {
        let (_dir, path) = kape_sample();
        let image = Image::open(&path).unwrap();
        let volume = &image.volumes[0];
        let record = record_of(volume, "C/Users/sample/Data/compressed/text.log");
        let runs = volume.fs.runs_by_record(record, None).unwrap();
        let first_cluster = runs.iter().find_map(|run| run.lcn).unwrap();
        let at = volume.start + first_cluster * volume.cluster_size;
        drop(image);
        patch_sample(&path, at, &[0xFF, 0xFF]);
        let image = Image::open(&path).unwrap();
        let volume = &image.volumes[0];
        // getattr must report the readable record's attributes without decompressing content.
        let stat = volume.stat(record).unwrap();
        assert_eq!(stat.size, 680_000);
        assert!(volume.read(record, 0, 20).is_err());
    }

    #[test]
    fn a_damaged_ntfs_partition_is_reported_without_hiding_the_readable_volume() {
        let (_dir, path) = kape_sample();
        // Add an NTFS-looking but unreadable second partition. Sector 64 is in the
        // fixture's unused boot-loader area, so the original NTFS volume stays readable.
        let mut entry = [0; 16];
        entry[4] = 0x07;
        entry[8..12].copy_from_slice(&64u32.to_le_bytes());
        entry[12..16].copy_from_slice(&1u32.to_le_bytes());
        patch_sample(&path, 446 + 16, &entry);
        let mut boot = [0; 512];
        boot[3..11].copy_from_slice(b"NTFS    ");
        patch_sample(&path, 64 * 512, &boot);
        let image = Image::open(&path).unwrap();
        assert_eq!(image.volumes.len(), 1);
        assert_eq!(image.problems.len(), 1);
        assert!(image.problems[0].starts_with("volume 2 at byte 32768:"));
        let volume = &image.volumes[0];
        let record = record_of(volume, "C/Users/sample/Data/small.txt");
        assert_eq!(volume.read(record, 0, 100).unwrap(), b"resident content\n");
    }

    fn gpt(table: u64, first: u64, last: u64) -> io::Cursor<Vec<u8>> {
        let mut bytes = vec![0; 4 * 512];
        let header = &mut bytes[512..512 + 92];
        header[..8].copy_from_slice(b"EFI PART");
        header[72..80].copy_from_slice(&table.to_le_bytes());
        header[80..84].copy_from_slice(&1u32.to_le_bytes());
        header[84..88].copy_from_slice(&128u32.to_le_bytes());
        bytes[1024] = 1;
        bytes[1056..1064].copy_from_slice(&first.to_le_bytes());
        bytes[1064..1072].copy_from_slice(&last.to_le_bytes());
        io::Cursor::new(bytes)
    }

    #[test]
    fn gpt_offsets_and_lengths_do_not_wrap() {
        assert_eq!(
            gpt_partitions(&mut gpt(2, 3, 4), 512).unwrap(),
            [(1536, 1024)]
        );
        assert!(gpt_partitions(&mut gpt(u64::MAX, 3, 4), 512).is_err());
        assert!(gpt_partitions(&mut gpt(2, u64::MAX, u64::MAX), 512).is_err());
        assert!(gpt_partitions(&mut gpt(2, 0, u64::MAX), 512).is_err());
    }

    #[test]
    fn extended_partition_cycles_are_not_duplicate_volumes() {
        let mut bytes = vec![0u8; 5 * 512];
        for lba in [1, 2] {
            let ebr = &mut bytes[lba * 512..(lba + 1) * 512];
            ebr[510..].copy_from_slice(&[0x55, 0xAA]);
            ebr[446 + 4] = 0x07;
            ebr[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
            ebr[446 + 12..446 + 16].copy_from_slice(&1u32.to_le_bytes());
            ebr[462 + 4] = 0x0F;
            ebr[462 + 8..462 + 12].copy_from_slice(&1u32.to_le_bytes());
        }
        assert!(extended_partitions(&mut io::Cursor::new(&bytes), 1, 512).is_err());
        // A properly terminated chain has two distinct logical partitions.
        bytes[2 * 512 + 462 + 4] = 0;
        assert_eq!(
            extended_partitions(&mut io::Cursor::new(&bytes), 1, 512).unwrap(),
            [(1024, 512), (1536, 512)]
        );
    }

    /// The record of `path` (`/`-separated, from the root) on `volume`.
    fn record_of(volume: &Volume, path: &str) -> u64 {
        path.split('/').fold(ROOT_RECORD, |record, name| {
            volume
                .lookup(record, name)
                .unwrap()
                .unwrap_or_else(|| panic!("{path}"))
                .record
        })
    }

    /// Every file under `record`, with its SHA-256, read `chunk` bytes at a time.
    fn files(
        volume: &Volume,
        record: u64,
        prefix: &str,
        chunk: usize,
        out: &mut Vec<(String, u64, String)>,
    ) {
        use sha2::{Digest, Sha256};
        for entry in volume.list(record).unwrap().iter() {
            let path = format!("{prefix}{}", entry.name);
            if entry.directory {
                files(volume, entry.record, &format!("{path}/"), chunk, out);
                continue;
            }
            let size = volume.stat(entry.record).unwrap().size;
            let mut hash = Sha256::new();
            let mut offset = 0;
            loop {
                let bytes = volume.read(entry.record, offset, chunk).unwrap();
                if bytes.is_empty() {
                    break;
                }
                offset += bytes.len() as u64;
                hash.update(&bytes);
            }
            assert_eq!(offset, size, "{path}");
            let digest = hash
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            out.push((path, size, digest));
        }
    }

    #[test]
    fn the_files_of_a_kape_vhdx() {
        let (_dir, path) = kape_sample();
        // the boot sector has no jump instruction and no 55 AA signature, as DiscUtils writes it
        let raw = std::fs::read(&path).unwrap();
        assert!(raw.windows(8).any(|w| w == b"NTFS    "));
        let image = Image::open(&path).unwrap();
        assert_eq!(image.size, 32 << 20);
        assert_eq!(image.volumes.len(), 1);
        let volume = &image.volumes[0];
        assert_eq!(volume.start, 63 * 512);
        // as ntfs-3g reads them (test_files/vhdx/README.md); in odd chunks, across runs
        for chunk in [4096, 777, 1 << 20] {
            let mut got = Vec::new();
            files(volume, record_of(volume, "C"), "C/", chunk, &mut got);
            got.sort();
            let want = [
                (
                    "C/Users/sample/Data/compressed/text.log",
                    680_000,
                    "cc3c52b090233f44ecfc2dbd90adc6c787e071872ca488fa96eae24af8162f98",
                ),
                (
                    "C/Users/sample/Data/empty.bin",
                    0,
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                ),
                (
                    "C/Users/sample/Data/fragmented.bin",
                    132_056,
                    "dad53fd22d62e1acbf48ababc172c8eb3ffb45486b261fb960a2990199a8e459",
                ),
                (
                    "C/Users/sample/Data/small.txt",
                    17,
                    "75be4d482645f0ca9490a06e70744a4315939324213c27ac29baa0453dcdb25b",
                ),
                (
                    "C/Users/sample/Data/spacer.bin",
                    131_072,
                    "5eb7ccaea156fe674474e30a611698f792325580924bc51200b2bfb133ff6230",
                ),
                (
                    "C/Users/sample/Data/sparse.bin",
                    2_097_152,
                    "72f63d8b7d68348852bb7cf5f735cbb3ade3a49dc1f19a5328ac6399897a4b61",
                ),
                (
                    "C/Users/sample/Data/日本語のファイル.txt",
                    32,
                    "5a22f4be6e911827cd009d96b7c484916d2141f4e98c6051ffb243dad7855f7f",
                ),
                (
                    "C/Windows/Prefetch/CMD.EXE-6D6290C5.pf",
                    2724,
                    "c53749078a97195d1c10320f4e3436026805254e489a7e8697f58cc78fe3c648",
                ),
                (
                    "C/Windows/System32/LogFiles/Sum/Current.mdb",
                    1_048_576,
                    "cb34a79a056475d8efb31ae525151a3664057a738f7a3fb7d9e7b7c212f413c3",
                ),
                (
                    "C/Windows/System32/LogFiles/Sum/SystemIdentity.mdb",
                    1_048_576,
                    "f2b146d212fed0488f18abc3f4805b4ae034f83d5cf26f5a92184ab344d33620",
                ),
                (
                    "C/Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler%4Operational.evtx",
                    69_632,
                    "6f00c7423da4ce91c6d3aa44dd81234cef24340c74e3209f78b5ce9395f0d90a",
                ),
            ];
            assert_eq!(
                got,
                want.map(|(p, s, h)| (p.to_string(), s, h.to_string())),
                "chunk {chunk}"
            );
        }
        // each kind of content is there
        let layout = |path: &str| volume.layout(record_of(volume, path)).unwrap();
        assert!(matches!(
            &*layout("C/Users/sample/Data/small.txt"),
            Layout::Resident(_)
        ));
        assert!(matches!(
            &*layout("C/Users/sample/Data/compressed/text.log"),
            Layout::Compressed { .. }
        ));
        assert!(
            matches!(&*layout("C/Users/sample/Data/fragmented.bin"), Layout::Runs { runs, .. } if runs.iter().filter(|r| r.lcn.is_some()).count() > 1)
        );
        assert!(
            matches!(&*layout("C/Users/sample/Data/sparse.bin"), Layout::Runs { runs, .. } if runs.iter().any(|r| r.lcn.is_none()))
        );
        // past the end, nothing; a read across the end, what is left
        let small = record_of(volume, "C/Users/sample/Data/small.txt");
        assert!(volume.read(small, 17, 10).unwrap().is_empty());
        assert_eq!(volume.read(small, 9, 100).unwrap(), b"content\n");
        // directories, names and times
        let data = record_of(volume, "C/Users/sample/Data");
        assert!(volume.stat(data).unwrap().directory);
        assert!(volume.lookup(data, "SMALL.TXT").unwrap().is_none());
        assert!(volume.lookup(ROOT_RECORD, "C").unwrap().unwrap().directory);
        assert!(volume.stat(small).unwrap().modified.0 > 0);
    }

    #[test]
    fn what_is_not_a_vhdx_or_holds_no_ntfs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not.vhdx");
        std::fs::write(&path, b"not a VHDX at all").unwrap();
        assert!(Image::open(&path).is_err());
        assert!(Image::open(&dir.path().join("missing.vhdx")).is_err());
    }

    #[test]
    fn primary_partition_entries() {
        let mut mbr = vec![0u8; 512];
        mbr[446 + 4] = 0x07;
        mbr[446 + 8..446 + 12].copy_from_slice(&63u32.to_le_bytes());
        mbr[446 + 12..446 + 16].copy_from_slice(&1000u32.to_le_bytes());
        mbr[446 + 16 + 4] = 0x05;
        mbr[446 + 16 + 8..446 + 16 + 12].copy_from_slice(&2048u32.to_le_bytes());
        assert_eq!(
            mbr_entries(&mbr),
            [(0x07, 63, 1000), (0x05, 2048, 0), (0, 0, 0), (0, 0, 0)]
        );
    }
}
