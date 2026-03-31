//! The low-level module for accessing sections in a DwarFS archive.
//!
//! A DwarFS archive consists of several sections. Sections for storing raw file
//! data are also called blocks. Each section consists of a [`Header`] and
//! maybe-compressed section payload bytes.
use std::{fmt, mem::offset_of};

use positioned_io::ReadAt;
use xxhash_rust::xxh3::Xxh3Default;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, little_endian as le};

use super::SUPPORTED_VERSION_RANGE;

type Result<T> = std::result::Result<T, Error>;

/// An error raised from reading, validating, or decompressing sections.
pub struct Error(Box<ErrorInner>);

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
enum ErrorInner {
    // Header.
    InvalidMagic([u8; 6]),
    UnsupportedVersion(u8, u8),
    LengthMismatch,
    ChecksumMismatch,
    OffsetOverflow,

    // Payload.
    UnsupportedCompressAlgo(CompressAlgo),
    TypeMismatch {
        expect: SectionType,
        got: SectionType,
    },
    PayloadTooLong {
        limit: usize,
        got: Option<u64>,
    },
    Decompress(std::io::Error),
    MalformedSectionIndex(String),

    // Other.
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self.0 {
            ErrorInner::InvalidMagic(magic) => {
                write!(f, "invalid section magic: b\"{}\"", magic.escape_ascii())
            }
            ErrorInner::UnsupportedVersion(maj, min) => {
                write!(f, "unsupported section version: DWARFS{maj}.{min}")
            }
            ErrorInner::LengthMismatch => f.pad("section payload length mismatch"),
            ErrorInner::ChecksumMismatch => f.pad("section checksum mismatch"),
            ErrorInner::OffsetOverflow => f.pad("section offset overflow"),

            ErrorInner::UnsupportedCompressAlgo(algo) => {
                write!(f, "unsupported section compress algorithm {algo:?}")
            }
            ErrorInner::TypeMismatch { expect, got } => {
                write!(
                    f,
                    "section type mismatch, expect {expect:?} but got {got:?}"
                )
            }
            ErrorInner::PayloadTooLong {
                limit,
                got: Some(got),
            } => {
                write!(
                    f,
                    "section payload has {got} bytes, exceeding the limit of {limit} bytes"
                )
            }
            ErrorInner::PayloadTooLong { limit, got: None } => {
                write!(f, "section payload exceeds the limit of {limit} bytes")
            }
            ErrorInner::MalformedSectionIndex(msg) => {
                write!(f, "malformed section index: {msg}")
            }

            ErrorInner::Decompress(err) => write!(f, "failed to decompress section payload: {err}"),

            ErrorInner::Io(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &*self.0 {
            ErrorInner::Decompress(err) | ErrorInner::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    #[cold]
    fn from(err: std::io::Error) -> Self {
        Self(Box::new(ErrorInner::Io(err)))
    }
}

impl From<ErrorInner> for Error {
    #[cold]
    fn from(err: ErrorInner) -> Self {
        Self(Box::new(err))
    }
}

pub(crate) const HEADER_SIZE: u64 = size_of::<Header>() as u64;

/// The section (aka. block) header.
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(8))]
pub struct Header {
    /// Header magic and format version.
    pub magic_version: MagicVersion,
    /// The "slow" hash digests of SHA-512/256.
    pub slow_hash: [u8; 32],
    /// The "fast" hash digests of XXH3-64.
    pub fast_hash: [u8; 8],
    /// The 0-based index of this section in the DwarFS archive.
    pub section_number: le::U32,
    /// The type of this section.
    pub section_type: SectionType,
    /// The compression algorithm of the section payload.
    pub compress_algo: CompressAlgo,
    /// The length in bytes of the compressed payload following.
    pub payload_size: le::U64,
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockHeader")
            .field("magic_version", &self.magic_version)
            .field("slow_hash", &format_args!("{:02x?}", self.slow_hash))
            .field("fast_hash", &format_args!("{:02x?}", self.fast_hash))
            .field("section_number", &self.section_number.get())
            .field("section_type", &self.section_type)
            .field("compress_algo", &self.compress_algo)
            .field("payload_size", &self.payload_size.get())
            .finish()
    }
}

impl Header {
    /// Calculate section checksum using the "fast" XXH3-64 hash.
    pub fn calculate_fast_checksum(&self, payload: &[u8]) -> Result<[u8; 8]> {
        if payload.len() as u64 != self.payload_size.get() {
            bail!(ErrorInner::LengthMismatch);
        }
        let mut h = Xxh3Default::new();
        h.update(&self.as_bytes()[offset_of!(Self, section_number)..]);
        h.update(payload);
        Ok(h.digest().to_le_bytes())
    }

    /// Validate section checksum using the "fast" XXH3-64 hash.
    pub fn validate_fast_checksum(&self, payload: &[u8]) -> Result<()> {
        let h = self.calculate_fast_checksum(payload)?;
        if h != self.fast_hash {
            bail!(ErrorInner::ChecksumMismatch);
        }
        Ok(())
    }

    /// Calculate section checksum using the "slow" SHA2-512/256 hash.
    pub fn calculate_slow_checksum(&self, payload: &[u8]) -> Result<[u8; 32]> {
        use sha2::Digest;

        if payload.len() as u64 != self.payload_size.get() {
            bail!(ErrorInner::LengthMismatch);
        }
        let mut h = sha2::Sha512_256::new();
        h.update(&self.as_bytes()[offset_of!(Self, fast_hash)..]);
        h.update(payload);
        Ok(*h.finalize().as_ref())
    }

    /// Validate section checksum using the "slow" SHA2-512/256 hash.
    pub fn validate_slow_checksum(&self, payload: &[u8]) -> Result<()> {
        let h = self.calculate_slow_checksum(payload)?;
        if h != self.slow_hash {
            bail!(ErrorInner::ChecksumMismatch);
        }
        Ok(())
    }

    /// Update `payload_size`, `fast_hash` and `slow_hash` in header for the specific `payload`.
    pub fn update_size_and_checksum(&mut self, payload: &[u8]) {
        self.payload_size = u64::try_from(payload.len())
            .expect("payload length overflows u64")
            .into();
        self.fast_hash = self
            .calculate_fast_checksum(payload)
            .expect("length matches");
        self.slow_hash = self
            .calculate_slow_checksum(payload)
            .expect("length matches");
    }

    /// Check if this section header has the expected section type.
    pub(crate) fn check_type(&self, expect: SectionType) -> Result<()> {
        if self.section_type != expect {
            bail!(ErrorInner::TypeMismatch {
                expect,
                got: self.section_type,
            });
        }
        Ok(())
    }

    fn payload_size_limited(&self, limit: usize) -> Result<usize> {
        let size = self.payload_size.get();
        if let Some(size) = usize::try_from(size).ok().filter(|&n| n <= limit) {
            Ok(size)
        } else {
            bail!(ErrorInner::PayloadTooLong {
                limit,
                got: Some(size)
            })
        }
    }
}

/// Section magic and format version.
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct MagicVersion {
    /// The section magic that should match `DWARFS` ([`MagicVersion::MAGIC`]).
    pub magic: [u8; 6],
    /// The format major version.
    pub major: u8,
    /// The format minor version.
    pub minor: u8,
}

impl fmt::Debug for MagicVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MagicVersion")
            .field("magic", &format_args!("b\"{}\"", self.magic.escape_ascii()))
            .field("major", &self.major)
            .field("minor", &self.minor)
            .finish()
    }
}

impl MagicVersion {
    /// The expected magic.
    pub const MAGIC: [u8; 6] = *b"DWARFS";

    /// The magic and latest supported version.
    pub const LATEST: Self = Self {
        magic: Self::MAGIC,
        major: SUPPORTED_VERSION_RANGE.end().0,
        minor: SUPPORTED_VERSION_RANGE.end().1,
    };

    /// Validate if the magic and version is supported.
    pub fn validate(self) -> Result<()> {
        let ver = (self.major, self.minor);
        if self.magic != Self::MAGIC {
            bail!(ErrorInner::InvalidMagic(self.magic));
        }
        if !SUPPORTED_VERSION_RANGE.contains(&ver) {
            bail!(ErrorInner::UnsupportedVersion(ver.0, ver.1));
        }
        Ok(())
    }
}

/// The type of a section.
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(2))]
pub struct SectionType(pub le::U16);

macro_rules! impl_open_enum {
    ($name:ident; $ctor:path; $($(#[$meta:meta])* $variant:ident = $value:expr,)*) => {
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.pad(match *self {
                    $(Self::$variant => stringify!($variant),)*
                    _ => return f
                        .debug_tuple(stringify!($name))
                        .field(&self.0.get())
                        .finish(),
                })
            }
        }

        impl $name {
            $(
                $(#[$meta])*
                pub const $variant: Self = Self($ctor($value));
            )*

            /// Return `true` if this value is known by the library.
            #[must_use]
            #[inline]
            pub fn is_known(self) -> bool {
                matches!(self, $(Self::$variant)|*)
            }
        }
    };
}

impl_open_enum! {
    SectionType; le::U16::new;

    /// A block of data.
    BLOCK = 0,
    /// The schema used to layout on-disk format of Metadata.
    METADATA_V2_SCHEMA = 7,
    /// The bulk of the root metadata.
    METADATA_V2 = 8,
    /// The index of all sections.
    SECTION_INDEX = 9,
    /// File system history information.
    HISTORY = 10,
}

/// Compression algorithm used for section payloads.
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(2))]
pub struct CompressAlgo(pub le::U16);

impl_open_enum! {
    CompressAlgo; le::U16::new;

    /// Not compressed.
    NONE = 0,
    /// LZMA, aka `.xz` compression.
    LZMA = 1,
    /// Zstd compression.
    ZSTD = 2,
    /// LZ4 compression.
    LZ4 = 3,
    /// LZ4 compression in HC (high-compression) mode.
    LZ4HC = 4,
    /// Brotli compression.
    BROTLI = 5,
    /// FLAC compression. Not supported.
    FLAC = 6,
    /// Rice++ compression. Not supported.
    RICEPP = 7,
}

/// An entry in the section index.
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(8))]
pub struct SectionIndexEntry(pub le::U64);

impl fmt::Debug for SectionIndexEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SectionIndexEntry")
            .field("section_type", &self.section_type())
            .field("offset", &self.offset())
            .finish()
    }
}

impl SectionIndexEntry {
    /// Create a section index entry with given section type and offset.
    #[must_use]
    #[inline]
    pub fn new(typ: SectionType, offset: u64) -> Option<Self> {
        if offset < 1u64 << 48 {
            Some(Self((u64::from(typ.0.get()) << 48 | offset).into()))
        } else {
            None
        }
    }

    /// The type of the section this entry is referring to.
    #[must_use]
    #[inline]
    #[allow(clippy::missing_panics_doc)]
    pub fn section_type(self) -> SectionType {
        SectionType((self.0 >> 48).try_into().expect("always in u16 range"))
    }

    /// The offset of the section this entry is referring to.
    #[must_use]
    #[inline]
    pub fn offset(self) -> u64 {
        self.0.get() & ((1u64 << 48) - 1)
    }
}

/// The wrapper type for reading sections from a random access reader.
pub struct SectionReader<R: ?Sized> {
    archive_start: u64,
    raw_buf: Vec<u8>,
    rdr: R,
}

impl<R: fmt::Debug + ?Sized> fmt::Debug for SectionReader<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SectionReader")
            .field("archive_start", &self.archive_start)
            .field(
                "raw_buf",
                &format_args!("{}/{}", self.raw_buf.len(), self.raw_buf.capacity()),
            )
            .field("rdr", &&self.rdr)
            .finish()
    }
}

impl<R> SectionReader<R> {
    /// Create a new section reader wrapping an existing random access stream.
    pub fn new(rdr: R) -> Self {
        Self::new_with_offset(rdr, 0)
    }

    /// Same as [`Self::new`] but with a starting offset for the archive.
    pub fn new_with_offset(rdr: R, archive_start: u64) -> Self {
        SectionReader {
            archive_start,
            raw_buf: Vec::new(),
            rdr,
        }
    }
}

impl<R: ?Sized> SectionReader<R> {
    #[inline]
    #[must_use]
    pub fn get_ref(&self) -> &R {
        &self.rdr
    }

    #[inline]
    #[must_use]
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.rdr
    }

    #[inline]
    #[must_use]
    pub fn into_inner(self) -> R
    where
        R: Sized,
    {
        self.rdr
    }
}

impl<R: ReadAt + ?Sized> SectionReader<R> {
    #[inline]
    #[must_use]
    pub fn archive_start(&self) -> u64 {
        self.archive_start
    }

    /// Read and decompress a full section at `offset` into memory.
    pub fn read_section_at(
        &mut self,
        section_offset: u64,
        payload_size_limit: usize,
    ) -> Result<(Header, Vec<u8>)> {
        let header = self.read_header_at(section_offset)?;
        let payload_offset = section_offset + HEADER_SIZE;
        let payload = self.read_payload_at(&header, payload_offset, payload_size_limit)?;
        Ok((header, payload))
    }

    /// Read a section header at `section_offset`.
    pub fn read_header_at(&mut self, section_offset: u64) -> Result<Header> {
        let file_offset = self
            .archive_start
            .checked_add(section_offset)
            .ok_or(ErrorInner::OffsetOverflow)?;
        let mut header = Header::new_zeroed();
        self.rdr.read_exact_at(file_offset, header.as_mut_bytes())?;
        header.magic_version.validate()?;
        Ok(header)
    }

    /// Read and decompress section payload into an owned `Vec<u8>`.
    pub fn read_payload_at(
        &mut self,
        header: &Header,
        payload_offset: u64,
        payload_size_limit: usize,
    ) -> Result<Vec<u8>> {
        let mut out = vec![0u8; payload_size_limit];
        let len = self.read_payload_at_into(header, payload_offset, &mut out)?;
        out.truncate(len);
        Ok(out)
    }

    /// Read and decompress section payload into a buffer.
    pub fn read_payload_at_into(
        &mut self,
        header: &Header,
        payload_offset: u64,
        out: &mut [u8],
    ) -> Result<usize> {
        let file_offset = self
            .archive_start
            .checked_add(payload_offset)
            .ok_or(ErrorInner::OffsetOverflow)?;

        let size_limit = out.len();
        let compressed_size = header.payload_size_limited(size_limit)?;
        let raw_buf = &mut self.raw_buf;
        raw_buf.resize(compressed_size, 0);
        self.rdr.read_exact_at(file_offset, raw_buf)?;
        header.validate_fast_checksum(raw_buf)?;

        match header.compress_algo {
            CompressAlgo::NONE => {
                out[..compressed_size].copy_from_slice(raw_buf);
                Ok(compressed_size)
            }
            CompressAlgo::ZSTD => zstd_safe::decompress(out, raw_buf).map_err(|code| {
                let msg = zstd_safe::get_error_name(code);
                ErrorInner::Decompress(std::io::Error::new(std::io::ErrorKind::InvalidData, msg))
                    .into()
            }),
            algo => Err(ErrorInner::UnsupportedCompressAlgo(algo).into()),
        }
    }

    /// Construct the section index by traversing all sections.
    pub fn build_section_index(
        &mut self,
        stream_len: u64,
        size_limit: usize,
    ) -> Result<Vec<SectionIndexEntry>> {
        let end_offset = stream_len
            .checked_sub(self.archive_start())
            .ok_or(ErrorInner::OffsetOverflow)?;

        let mut offset = 0u64;
        let mut index = Vec::with_capacity(size_limit / size_of::<SectionIndexEntry>());
        while offset < end_offset {
            let header = self.read_header_at(offset)?;
            let ent = SectionIndexEntry::new(header.section_type, offset)
                .ok_or(ErrorInner::OffsetOverflow)?;
            if index.len() == index.capacity() {
                bail!(ErrorInner::PayloadTooLong {
                    limit: size_limit,
                    got: None,
                });
            }
            index.push(ent);

            offset = (offset + HEADER_SIZE)
                .checked_add(header.payload_size.get())
                .ok_or(ErrorInner::OffsetOverflow)?;
        }
        if offset != end_offset {
            bail!(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected end of file"
            ));
        }
        Ok(index)
    }

    /// Locate and read the section index, if there is any.
    #[allow(clippy::missing_panics_doc)]
    pub fn read_section_index(
        &mut self,
        stream_len: u64,
        payload_size_limit: usize,
    ) -> Result<Option<(Header, Vec<SectionIndexEntry>)>> {
        const INDEX_ENTRY_SIZE64: u64 = size_of::<SectionIndexEntry>() as u64;
        const SECTION_INDEX_MIN_VERSION: (u8, u8) = (2, 4);

        // 1
        let first_magic = self.read_header_at(0)?.magic_version;
        if (first_magic.major, first_magic.minor) < SECTION_INDEX_MIN_VERSION {
            return Ok(None);
        }

        // 2
        let mut last_entry = SectionIndexEntry::new_zeroed();
        self.rdr
            .read_exact_at(stream_len - INDEX_ENTRY_SIZE64, last_entry.as_mut_bytes())?;
        if last_entry.section_type() != SectionType::SECTION_INDEX {
            return Ok(None);
        }

        // 3
        let index_header_offset = last_entry.offset();
        let Ok(header) = self.read_header_at(index_header_offset) else {
            return Ok(None);
        };
        let payload_size = header.payload_size.get();
        let num_sections = payload_size / INDEX_ENTRY_SIZE64;
        if payload_size != stream_len - index_header_offset - HEADER_SIZE
            || payload_size % INDEX_ENTRY_SIZE64 != 0
            || header.section_type != SectionType::SECTION_INDEX
            || header.compress_algo != CompressAlgo::NONE
            || u64::from(header.section_number.get()) != num_sections - 1
        {
            return Ok(None);
        }

        // 4
        if payload_size > payload_size_limit as u64 {
            bail!(ErrorInner::PayloadTooLong {
                got: Some(payload_size),
                limit: payload_size_limit
            });
        }
        let mut entries =
            SectionIndexEntry::new_vec_zeroed(num_sections as usize).expect("alloc failed");
        let buf_bytes = entries.as_mut_bytes();
        debug_assert_eq!(buf_bytes.len() as u64, payload_size);
        self.rdr
            .read_exact_at(index_header_offset + HEADER_SIZE, buf_bytes)?;

        header.validate_fast_checksum(buf_bytes)?;

        let mut prev = None;
        for (i, ent) in entries.iter().enumerate() {
            let (typ, offset) = (ent.section_type(), ent.offset());
            if !typ.is_known() {
                bail!(ErrorInner::MalformedSectionIndex(format!(
                    "entry {i} has unknown section type {typ:?}",
                )))
            }
            if prev.is_some_and(|prev| prev >= offset) {
                bail!(ErrorInner::MalformedSectionIndex(format!(
                    "entry {i} has unsorted offset {offset} >= previous offset {prev:?}",
                )));
            }
            prev = Some(offset)
        }

        Ok(Some((header, entries)))
    }
}
