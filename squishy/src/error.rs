use std::path::PathBuf;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SquishyError {
    #[error("Failed to find SquashFS magic bytes in the file")]
    NoSquashFsFound,

    #[error("Failed to find DwarFS magic bytes in the file")]
    NoDwarFsFound,

    #[error("Failed to find any supported filesystem in the file")]
    NoFilesystemFound,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SquashFS error: {0}")]
    InvalidSquashFS(String),

    #[error("DwarFS error: {0}")]
    InvalidDwarFS(String),

    #[error("Symlink error: {0}")]
    SymlinkError(String),

    #[error("File not found: {0}")]
    FileNotFound(PathBuf),
}
