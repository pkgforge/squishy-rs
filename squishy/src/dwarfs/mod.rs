use std::{
    collections::HashSet,
    fs::{self, File, Permissions},
    io::{BufWriter, Read, Seek, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use positioned_io::Slice;

use archive::{Archive, ArchiveIndex, AsChunks, InodeKind};

use crate::error::SquishyError;

// --- Internal macros used by submodules ---

macro_rules! bail {
    ($err:expr $(,)?) => {
        return Err(Into::into($err))
    };
}

macro_rules! trace {
    ($($tt:tt)*) => {
        let _ = if false {
            let _ = ::std::format_args!($($tt)*);
        };
    };
}

macro_rules! trace_time {
    ($($tt:tt)*) => {
        trace!($($tt)*)
    };
}

/// The range of filesystem version tuple `(major, minor)` supported by this library.
///
/// Currently this is `(2, 3)..=(2, 5)`.
pub const SUPPORTED_VERSION_RANGE: std::ops::RangeInclusive<(u8, u8)> = (2, 3)..=(2, 5);

// --- Submodules (ported from dwarfs-rs) ---

pub mod archive;
pub mod fsst;
pub mod metadata;
pub mod section;

// --- High-level wrapper types ---

pub type Result<T> = std::result::Result<T, SquishyError>;

/// Magic bytes for DwarFS filesystem
pub const DWARFS_MAGIC: &[u8] = b"DWARFS";

/// The DwarFS struct provides an interface for reading and interacting with a DwarFS filesystem.
pub struct DwarFS {
    index: ArchiveIndex,
    archive: Archive<Slice<File>>,
}

/// The DwarFSEntry struct represents a single file or directory entry within the DwarFS filesystem.
#[derive(Debug)]
pub struct DwarFSEntry {
    pub path: PathBuf,
    pub size: u64,
    pub mode: u32,
    pub kind: DwarFSEntryKind,
}

/// The DwarFSEntryKind enum represents the different types of entries that can be found in the DwarFS filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DwarFSEntryKind {
    File,
    Directory,
    Symlink(PathBuf),
    Device,
    Ipc,
    Unknown,
}

impl DwarFS {
    /// Creates a new DwarFS instance from a file path with an offset.
    pub fn from_path_with_offset<P: AsRef<Path>>(path: P, offset: u64) -> Result<Self> {
        let file = File::open(path.as_ref())?;
        let file_size = file.metadata()?.len();
        let slice_len = file_size.saturating_sub(offset);
        let reader = Slice::new(file, offset, Some(slice_len));
        let (index, archive) = Archive::new(reader).map_err(|e| {
            SquishyError::InvalidDwarFS(format!("Failed to parse DwarFS archive: {e}"))
        })?;

        Ok(Self { index, archive })
    }

    /// Creates a new DwarFS instance from a file path. Tries to find offset automatically.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(path.as_ref())?;
        let offset = Self::find_dwarfs_offset(&mut file)?;
        Self::from_path_with_offset(path, offset)
    }

    /// Finds the starting offset of the DwarFS data within the input file.
    pub fn find_dwarfs_offset(file: &mut File) -> Result<u64> {
        let mut buf = [0u8; 8];
        while file.read_exact(&mut buf).is_ok() {
            if &buf[..6] == DWARFS_MAGIC && buf[6] == 2 {
                let found = file.stream_position()? - buf.len() as u64;
                file.rewind()?;
                return Ok(found);
            }
            file.seek(std::io::SeekFrom::Current(-7))?;
        }
        Err(SquishyError::NoDwarFsFound)
    }

    /// Returns an iterator over all the entries in the DwarFS filesystem.
    pub fn entries(&self) -> impl Iterator<Item = DwarFSEntry> + '_ {
        self.walk_dir(self.index.root(), PathBuf::from("/"))
    }

    /// Recursively walks a directory and yields entries
    fn walk_dir<'a>(
        &'a self,
        dir: archive::Dir<'a>,
        base_path: PathBuf,
    ) -> Box<dyn Iterator<Item = DwarFSEntry> + 'a> {
        let entries_iter = dir.entries().flat_map(move |entry| {
            let name = entry.name();
            let path = base_path.join(name);
            let inode = entry.inode();
            let mode = inode.metadata().file_type_mode().mode_bits();

            let (kind, size) = match inode.classify() {
                InodeKind::Directory(d) => {
                    let dir_entry = DwarFSEntry {
                        path: path.clone(),
                        size: 0,
                        mode,
                        kind: DwarFSEntryKind::Directory,
                    };
                    let sub_entries = self.walk_dir(d, path);
                    return Box::new(std::iter::once(dir_entry).chain(sub_entries))
                        as Box<dyn Iterator<Item = DwarFSEntry>>;
                }
                InodeKind::File(f) => (DwarFSEntryKind::File, f.as_chunks().total_size()),
                InodeKind::Symlink(s) => (DwarFSEntryKind::Symlink(PathBuf::from(s.target())), 0),
                InodeKind::Device(_) => (DwarFSEntryKind::Device, 0),
                InodeKind::Ipc(_) => (DwarFSEntryKind::Ipc, 0),
            };

            Box::new(std::iter::once(DwarFSEntry {
                path,
                size,
                mode,
                kind,
            })) as Box<dyn Iterator<Item = DwarFSEntry>>
        });

        Box::new(entries_iter)
    }

    /// Returns an iterator over all the entries in the DwarFS filesystem
    /// that match the provided predicate function.
    pub fn find_entries<F>(&self, predicate: F) -> impl Iterator<Item = DwarFSEntry> + '_
    where
        F: Fn(&Path) -> bool + 'static,
    {
        self.entries().filter(move |entry| predicate(&entry.path))
    }

    /// Reads the contents of the specified file from the DwarFS filesystem.
    pub fn read_file<P: AsRef<Path>>(&mut self, path: P) -> Result<Vec<u8>> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy();
        let path_components: Vec<&str> = path_str
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let inode = self
            .index
            .get_path(path_components.iter())
            .ok_or_else(|| SquishyError::FileNotFound(path.to_path_buf()))?;

        let file = inode.as_file().ok_or_else(|| {
            SquishyError::InvalidDwarFS(format!("{} is not a file", path.display()))
        })?;

        file.read_to_vec(&mut self.archive)
            .map_err(|e| SquishyError::Io(e))
    }

    /// Writes the contents of the specified file from the DwarFS filesystem
    /// to the specified destination path.
    pub fn write_file<P: AsRef<Path>>(&mut self, entry: &DwarFSEntry, dest: P) -> Result<()> {
        if entry.kind != DwarFSEntryKind::File {
            return Err(SquishyError::InvalidDwarFS("Entry is not a file".into()));
        }

        let contents = self.read_file(&entry.path)?;
        let output_file = File::create(&dest)?;
        let mut writer = BufWriter::new(output_file);
        writer.write_all(&contents)?;

        Ok(())
    }

    /// Writes the contents of the specified file from the DwarFS filesystem
    /// to the specified destination path with permissions.
    pub fn write_file_with_permissions<P: AsRef<Path>>(
        &mut self,
        entry: &DwarFSEntry,
        dest: P,
    ) -> Result<()> {
        self.write_file(entry, &dest)?;
        fs::set_permissions(&dest, Permissions::from_mode(entry.mode))?;
        Ok(())
    }

    /// Resolves the symlink chain starting from the specified entry,
    /// returning the final target entry or an error if a cycle is detected.
    pub fn resolve_symlink(&self, entry: &DwarFSEntry) -> Result<Option<DwarFSEntry>> {
        match &entry.kind {
            DwarFSEntryKind::Symlink(target) => {
                let mut visited = HashSet::new();
                visited.insert(entry.path.clone());
                self.follow_symlink(target, &mut visited)
            }
            _ => Ok(None),
        }
    }

    /// Recursively follows symlinks, keeping track of the visited paths
    /// to detect and report cycles.
    fn follow_symlink(
        &self,
        target: &Path,
        visited: &mut HashSet<PathBuf>,
    ) -> Result<Option<DwarFSEntry>> {
        if !visited.insert(target.to_path_buf()) {
            return Err(SquishyError::SymlinkError("Cyclic symlink detected".into()));
        }

        let target_path = target.to_path_buf();

        if let Some(target_entry) = self
            .find_entries(move |p| p == target_path.as_path())
            .next()
        {
            match &target_entry.kind {
                DwarFSEntryKind::Symlink(next_target) => self.follow_symlink(next_target, visited),
                _ => Ok(Some(target_entry)),
            }
        } else {
            Ok(None)
        }
    }
}
