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

//! A disk image's NTFS volumes as a read-only FUSE file system (fuser, without libfuse): the
//! files of the image's one volume at the mount point, or `Volume1`, `Volume2`, … when it has
//! several. The mount refuses writes, the content never changes, so the kernel may cache it.
//! Unmounting is the caller's: [`Mounted`] unmounts when dropped, and [`unmount_on_interrupt`]
//! unmounts on Ctrl-C, SIGTERM or SIGHUP.

use crate::image::{Entry, Image, ROOT_RECORD, Stat};
use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, LockOwner,
    MountOption, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyOpen,
    ReplyStatfs, Request, SessionUnmounter,
};
use std::ffi::OsStr;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The content never changes: the kernel may keep names and attributes this long.
const TTL: Duration = Duration::from_secs(3600);
/// Threads serving one mount.
const THREADS: usize = 4;
/// An inode's volume is in its top 16 bits; its record, plus this, below.
const RECORD_BIAS: u64 = 16;

/// What an inode number stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Node {
    /// The mount point of an image with several volumes: `Volume1`, `Volume2`, …
    Volumes,
    /// A record of a volume.
    Record(usize, u64),
}

/// The image's volumes, served read-only.
struct ImageFs {
    image: Image,
    uid: u32,
    gid: u32,
}

impl ImageFs {
    fn node(&self, ino: INodeNo) -> Option<Node> {
        let ino = u64::from(ino);
        if ino == INodeNo::ROOT.0 {
            return Some(if self.image.volumes.len() == 1 {
                Node::Record(0, ROOT_RECORD)
            } else {
                Node::Volumes
            });
        }
        let volume = (ino >> 48) as usize;
        let record = (ino & ((1 << 48) - 1)).checked_sub(RECORD_BIAS)?;
        (volume < self.image.volumes.len()).then_some(Node::Record(volume, record))
    }

    fn ino(&self, volume: usize, record: u64) -> INodeNo {
        if self.image.volumes.len() == 1 && record == ROOT_RECORD {
            INodeNo::ROOT
        } else {
            INodeNo(((volume as u64) << 48) | (record + RECORD_BIAS))
        }
    }

    fn volume_name(index: usize) -> String {
        format!("Volume{}", index + 1)
    }

    fn attr(&self, ino: INodeNo, stat: &Stat) -> FileAttr {
        FileAttr {
            ino,
            size: stat.size,
            blocks: stat.size.div_ceil(512),
            atime: system_time(stat.accessed.0),
            mtime: system_time(stat.modified.0),
            ctime: system_time(stat.changed.0),
            crtime: system_time(stat.created.0),
            kind: if stat.directory {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            perm: if stat.directory { 0o555 } else { 0o444 },
            nlink: if stat.directory { 2 } else { 1 },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        }
    }

    fn volumes_attr(&self) -> FileAttr {
        FileAttr {
            ino: INodeNo::ROOT,
            size: 0,
            blocks: 0,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::Directory,
            perm: 0o555,
            nlink: 2,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        }
    }

    fn stat(&self, volume: usize, record: u64) -> Result<Stat, Errno> {
        self.image.volumes[volume].stat(record).map_err(errno)
    }

    fn entries(&self, node: Node) -> Result<Vec<(INodeNo, FileType, String)>, Errno> {
        match node {
            Node::Volumes => Ok((0..self.image.volumes.len())
                .map(|i| {
                    (
                        self.ino(i, ROOT_RECORD),
                        FileType::Directory,
                        Self::volume_name(i),
                    )
                })
                .collect()),
            Node::Record(volume, record) => Ok(self.image.volumes[volume]
                .list(record)
                .map_err(errno)?
                .iter()
                .map(|e: &Entry| {
                    let kind = if e.directory {
                        FileType::Directory
                    } else {
                        FileType::RegularFile
                    };
                    (self.ino(volume, e.record), kind, e.name.clone())
                })
                .collect()),
        }
    }
}

impl Filesystem for ImageFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(name) = name.to_str() else {
            return reply.error(Errno::ENOENT);
        };
        let found = match self.node(parent) {
            Some(Node::Volumes) => (0..self.image.volumes.len())
                .find(|&i| Self::volume_name(i) == name)
                .map(|i| (i, ROOT_RECORD)),
            Some(Node::Record(volume, record)) => {
                match self.image.volumes[volume].lookup(record, name) {
                    Ok(entry) => entry.map(|e| (volume, e.record)),
                    Err(e) => return reply.error(errno(e)),
                }
            }
            None => None,
        };
        match found {
            Some((volume, record)) => match self.stat(volume, record) {
                Ok(stat) => reply.entry(
                    &TTL,
                    &self.attr(self.ino(volume, record), &stat),
                    Generation(0),
                ),
                Err(e) => reply.error(e),
            },
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.node(ino) {
            Some(Node::Volumes) => reply.attr(&TTL, &self.volumes_attr()),
            Some(Node::Record(volume, record)) => match self.stat(volume, record) {
                Ok(stat) => reply.attr(&TTL, &self.attr(ino, &stat)),
                Err(e) => reply.error(e),
            },
            None => reply.error(Errno::ENOENT),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        if flags.0 & libc_access_mode() != 0 {
            return reply.error(Errno::EROFS);
        }
        match self.node(ino) {
            Some(Node::Record(volume, record)) => match self.stat(volume, record) {
                Ok(stat) if !stat.directory => {
                    reply.opened(FileHandle(0), FopenFlags::FOPEN_KEEP_CACHE)
                }
                Ok(_) => reply.error(Errno::EISDIR),
                Err(e) => reply.error(e),
            },
            Some(Node::Volumes) => reply.error(Errno::EISDIR),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        match self.node(ino) {
            Some(Node::Record(volume, record)) => {
                match self.image.volumes[volume].read(record, offset, size as usize) {
                    Ok(bytes) => reply.data(&bytes),
                    Err(e) => reply.error(errno(e)),
                }
            }
            _ => reply.error(Errno::EISDIR),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let Some(node) = self.node(ino) else {
            return reply.error(Errno::ENOENT);
        };
        let entries = match self.entries(node) {
            Ok(entries) => entries,
            Err(e) => return reply.error(e),
        };
        let dots = [
            (ino, FileType::Directory, ".".to_string()),
            (INodeNo::ROOT, FileType::Directory, "..".to_string()),
        ];
        for (i, (child, kind, name)) in dots
            .into_iter()
            .chain(entries)
            .enumerate()
            .skip(offset as usize)
        {
            if reply.add(child, (i + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let blocks = self.image.volumes.iter().map(|v| v.len / 4096).sum();
        reply.statfs(blocks, 0, 0, 0, 0, 4096, 255, 4096);
    }
}

/// `O_WRONLY | O_RDWR`: the access modes that write.
const fn libc_access_mode() -> i32 {
    0o1 | 0o2
}

/// A FILETIME as a system time (the epoch for 0).
fn system_time(filetime: u64) -> SystemTime {
    const UNIX_IN_FILETIME: u64 = 116_444_736_000_000_000;
    if filetime == 0 {
        return UNIX_EPOCH;
    }
    let ticks = i128::from(filetime) - i128::from(UNIX_IN_FILETIME);
    let magnitude = ticks.unsigned_abs();
    let duration = Duration::new(
        (magnitude / 10_000_000) as u64,
        ((magnitude % 10_000_000) * 100) as u32,
    );
    if ticks >= 0 {
        UNIX_EPOCH.checked_add(duration).unwrap_or(UNIX_EPOCH)
    } else {
        UNIX_EPOCH.checked_sub(duration).unwrap_or(UNIX_EPOCH)
    }
}

fn errno(e: io::Error) -> Errno {
    match e.kind() {
        io::ErrorKind::NotFound => Errno::ENOENT,
        _ => Errno::EIO,
    }
}

/// An image mounted read-only, unmounted when dropped.
pub struct Mounted {
    pub mount_point: PathBuf,
    /// The volumes: (start on the disk, length) in bytes.
    pub volumes: Vec<(u64, u64)>,
    pub problems: Vec<String>,
    session: Option<MountedSession>,
}

/// Keep the session's mount ownership shared with every registered unmount handle.
struct MountedSession {
    unmounter: SessionUnmounter,
    worker: JoinHandle<io::Result<()>>,
}

impl MountedSession {
    fn unmount_and_join(mut self) -> io::Result<()> {
        self.unmounter.unmount()?;
        self.worker
            .join()
            .map_err(|_| io::Error::other("filesystem background thread panicked"))?
    }
}

impl Mounted {
    /// Unmount, waiting for the file system to stop.
    ///
    /// # Errors
    /// When it can't be unmounted (a file is still in use).
    pub fn unmount(mut self) -> io::Result<()> {
        match self.session.take() {
            Some(session) => session.unmount_and_join(),
            None => Ok(()),
        }
    }
}

impl Drop for Mounted {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            let _ = session.unmount_and_join();
        }
    }
}

/// Mount `image`'s NTFS volumes read-only at `mount_point` (an existing directory), served by
/// background threads. `unmounters` gets what unmounts it on an interrupt.
///
/// # Errors
/// When the image can't be read or FUSE can't mount it.
pub fn mount(
    image: &Path,
    mount_point: &Path,
    unmounters: &Arc<Mutex<Vec<SessionUnmounter>>>,
) -> io::Result<Mounted> {
    mount_image(Image::open(image)?, image, mount_point, unmounters)
}

/// Mount an opened image's NTFS volumes read-only at `mount_point`, as [`mount`] does: for disks
/// that [`Image::from_disk`] opened. `path` is the image's file, which names the file system.
///
/// # Errors
/// When FUSE can't mount it.
pub fn mount_image(
    opened: Image,
    path: &Path,
    mount_point: &Path,
    unmounters: &Arc<Mutex<Vec<SessionUnmounter>>>,
) -> io::Result<Mounted> {
    // Serialize mount creation and registration with the interrupt handler. Otherwise
    // an interrupt could exit after the mount is attached but before its handle is listed.
    let mut list = unmounters
        .lock()
        .map_err(|_| io::Error::other("mount registry lock poisoned"))?;
    let volumes = opened.volumes.iter().map(|v| (v.start, v.len)).collect();
    let problems = opened.problems.clone();
    let session = new_session(opened, path, mount_point)?;
    let mut session = session;
    let unmounter = session.unmount_callable();
    let registered = session.unmount_callable();
    // fuser::Session::spawn moves the mount out of the shared handle, making earlier
    // SessionUnmounters no-ops. Run the session ourselves to retain shared ownership.
    let worker = thread::Builder::new()
        .name("ys-vhdx-fuse".to_string())
        .spawn(move || session.run())?;
    list.push(registered);
    let session = MountedSession { unmounter, worker };
    Ok(Mounted {
        mount_point: mount_point.to_path_buf(),
        volumes,
        problems,
        session: Some(session),
    })
}

/// A FUSE session serving `image`'s volumes at `mount_point`, not yet running.
pub fn new_session(
    image: Image,
    path: &Path,
    mount_point: &Path,
) -> io::Result<fuser::Session<impl Filesystem + 'static>> {
    let owner = std::fs::metadata(mount_point)?;
    if !owner.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a directory", mount_point.display()),
        ));
    }
    let name = path
        .file_name()
        .map_or_else(|| "image".into(), |n| n.to_string_lossy().replace(',', "_"));
    let mut config = fuser::Config::default();
    config.mount_options = vec![
        MountOption::RO,
        MountOption::NoExec,
        MountOption::NoSuid,
        MountOption::NoDev,
        MountOption::FSName(format!("juntei:{name}")),
        MountOption::Subtype("juntei".to_string()),
    ];
    config.n_threads = Some(THREADS);
    let fs = ImageFs {
        image,
        uid: owner.uid(),
        gid: owner.gid(),
    };
    fuser::Session::new(fs, mount_point, &config)
}

/// Unmount everything in `unmounters` on Ctrl-C, SIGTERM or SIGHUP, then remove the empty mount
/// points in `mount_points` and the directory itself, and exit with `code` (`None`: return and let
/// the program end on its own, as when it waits for its one mount).
///
/// # Errors
/// When the handler can't be installed (one already is).
pub fn unmount_on_interrupt(
    unmounters: Arc<Mutex<Vec<SessionUnmounter>>>,
    mount_points: Option<PathBuf>,
    code: Option<i32>,
) -> io::Result<()> {
    ctrlc::set_handler(move || {
        // Retain the registry lock through process exit: a waiting mount must not
        // attach a new image after this handler has finished walking the list.
        let mut list = unmounters.lock().unwrap_or_else(|e| e.into_inner());
        for unmounter in list.iter_mut() {
            if let Err(e) = unmounter.unmount() {
                eprintln!("Could not unmount an image after interruption: {e}");
            }
        }
        if let Some(directory) = &mount_points {
            remove_mount_points(directory);
        }
        if let Some(code) = code {
            std::process::exit(code);
        }
    })
    .map_err(io::Error::other)
}

/// Remove `directory` and the mount points in it, which must be empty: a directory something is
/// still mounted at, or that holds anything, stays.
pub fn remove_mount_points(directory: &Path) {
    if let Ok(entries) = std::fs::read_dir(directory) {
        for entry in entries.flatten() {
            let _ = std::fs::remove_dir(entry.path());
        }
    }
    let _ = std::fs::remove_dir(directory);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetimes_as_system_times() {
        assert_eq!(system_time(0), UNIX_EPOCH);
        assert_eq!(system_time(116_444_736_000_000_000), UNIX_EPOCH);
        // 2023-01-11T03:54:53Z
        assert_eq!(
            system_time(133_178_828_930_000_000),
            UNIX_EPOCH + Duration::from_secs(1_673_409_293)
        );
        // before 1970
        assert_eq!(
            system_time(1),
            UNIX_EPOCH - Duration::from_nanos(11_644_473_599_999_999_900)
        );
        // Valid NTFS times beyond 2554 must not be clamped to u64::MAX nanoseconds.
        assert_eq!(
            system_time(441_481_536_000_000_001),
            UNIX_EPOCH + Duration::new(32_503_680_000, 100)
        );
    }
}
