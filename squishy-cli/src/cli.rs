use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    author,
    version,
    about,
    help_template = "{before-help}{name} {version}
{author-with-newline}{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}",
    arg_required_else_help = true
)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Commands,

    #[clap(required = false, long, short)]
    pub quiet: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// AppImage specific tasks
    #[command(arg_required_else_help = true)]
    #[clap(name = "appimage", alias = "ai")]
    AppImage {
        /// Path to appimage file
        #[arg(required = true)]
        file: PathBuf,

        /// Offset
        #[arg(required = false, long, short)]
        offset: Option<u64>,

        /// Filter to apply
        #[arg(required = false, long, short)]
        filter: Option<String>,

        /// Whether to search for icon
        #[arg(required = false, long, short)]
        icon: bool,

        /// Whether to search for desktop file
        #[arg(required = false, long, short)]
        desktop: bool,

        /// Whether to search for appstream file
        #[arg(required = false, long, short)]
        appstream: bool,

        /// Whether to write files to disk
        #[arg(required = false, long, short)]
        write: Option<Option<PathBuf>>,

        /// Whether to extract the file with the original name from the squashfs inside the AppImage
        #[arg(required = false, long = "original-name")]
        original_name: bool,

        /// Copy permissions from the squashfs entry
        #[arg(required = false, long)]
        copy_permissions: bool,
    },

    Unsquashfs {
        /// Path to squashfs file
        #[arg(required = true)]
        file: PathBuf,

        /// Offset
        #[arg(required = false, long, short)]
        offset: Option<u64>,

        /// Whether to write files to disk
        #[arg(required = false, long, short)]
        write: Option<Option<PathBuf>>,
    },

    /// Extract DwarFS filesystem
    #[cfg(feature = "dwarfs")]
    DwarfsExtract {
        /// Path to dwarfs file
        #[arg(required = true)]
        file: PathBuf,

        /// Offset
        #[arg(required = false, long, short)]
        offset: Option<u64>,

        /// Whether to write files to disk
        #[arg(required = false, long, short)]
        write: Option<Option<PathBuf>>,
    },
}
