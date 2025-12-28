use std::{
    fs::{self, Permissions},
    os::unix::{self, fs::PermissionsExt},
};

use clap::Parser;
use cli::Args;
use rayon::iter::ParallelIterator;
use squishy::{
    appimage::{get_offset, AppImage},
    error::SquishyError,
    EntryKind, SquashFS,
};

mod cli;

macro_rules! log {
    ($quiet:expr, $($arg:tt)*) => {
        if !$quiet {
            println!($($arg)*);
        }
    };
}

macro_rules! elog {
    ($quiet:expr, $($arg:tt)*) => {
        if !$quiet {
            eprintln!($($arg)*);
        }
    };
}

fn main() {
    let args = Args::parse();

    match args.command {
        cli::Commands::AppImage {
            offset,
            filter,
            file,
            icon,
            desktop,
            appstream,
            write,
            original_name,
            copy_permissions: _,
        } => {
            if file.exists() {
                let mut appimage = match AppImage::new(filter.as_deref(), &file, offset) {
                    Ok(appimage) => appimage,
                    Err(e) => {
                        elog!(args.quiet, "{}", e);
                        std::process::exit(-1);
                    }
                };

                let write_path = if let Some(write) = write {
                    if let Some(path) = write {
                        Some(path)
                    } else {
                        Some(std::env::current_dir().unwrap())
                    }
                } else {
                    None
                };

                let output_name = if original_name {
                    None
                } else {
                    file.file_name()
                };

                if desktop {
                    if let Some(desktop) = appimage.find_desktop() {
                        if let Some(ref write_path) = write_path {
                            let file_name = get_output_filename(&desktop.path, output_name);
                            fs::create_dir_all(write_path).unwrap();
                            let output_path = write_path.join(file_name);
                            match appimage.write_entry(&desktop, &output_path) {
                                Ok(_) => log!(args.quiet, "Wrote {} to {}", desktop.path.display(), output_path.display()),
                                Err(e) => elog!(args.quiet, "Failed to write desktop: {}", e),
                            }
                        } else {
                            log!(args.quiet, "Desktop file: {}", desktop.path.display());
                        }
                    } else {
                        elog!(args.quiet, "No desktop file found.");
                    };
                }
                if icon {
                    if let Some(icon) = appimage.find_icon() {
                        if let Some(ref write_path) = write_path {
                            let file_name = get_output_filename(&icon.path, output_name);
                            fs::create_dir_all(write_path).unwrap();
                            let output_path = write_path.join(file_name);
                            match appimage.write_entry(&icon, &output_path) {
                                Ok(_) => log!(args.quiet, "Wrote {} to {}", icon.path.display(), output_path.display()),
                                Err(e) => elog!(args.quiet, "Failed to write icon: {}", e),
                            }
                        } else {
                            log!(args.quiet, "Icon: {}", icon.path.display());
                        }
                    } else {
                        elog!(args.quiet, "No icon found.");
                    };
                }
                if appstream {
                    if let Some(appstream) = appimage.find_appstream() {
                        if let Some(ref write_path) = write_path {
                            let file_name = get_output_filename(&appstream.path, output_name);
                            fs::create_dir_all(write_path).unwrap();
                            let output_path = write_path.join(file_name);
                            match appimage.write_entry(&appstream, &output_path) {
                                Ok(_) => log!(args.quiet, "Wrote {} to {}", appstream.path.display(), output_path.display()),
                                Err(e) => elog!(args.quiet, "Failed to write appstream: {}", e),
                            }
                        } else {
                            log!(args.quiet, "Appstream file: {}", appstream.path.display());
                        }
                    } else {
                        elog!(args.quiet, "No appstream file found.");
                    };
                }
            }
        }
        cli::Commands::Unsquashfs {
            offset,
            file,
            write,
        } => {
            let write_path = if let Some(write) = write {
                if let Some(path) = write {
                    fs::create_dir_all(&path).unwrap();
                    Some(path)
                } else {
                    Some(std::env::current_dir().unwrap())
                }
            } else {
                None
            };

            let offset = offset.unwrap_or(get_offset(&file).unwrap());
            let squashfs = SquashFS::from_path_with_offset(&file, offset)
                .map_err(|_| {
                    SquishyError::InvalidSquashFS(
                        "Couldn't find squashfs. Try providing valid offset.".to_owned(),
                    )
                })
                .unwrap();

            squashfs.par_entries().for_each(|entry| {
                if let Some(output_dir) = &write_path {
                    let file_path = entry.path.strip_prefix("/").unwrap_or(&entry.path);
                    let output_path = output_dir.join(file_path);
                    fs::create_dir_all(output_path.parent().unwrap()).unwrap();

                    match &entry.kind {
                        EntryKind::File(squashfs_file) => {
                            if output_path.exists() {
                                return;
                            }
                            let _ = squashfs.write_file_with_permissions(
                                squashfs_file,
                                &output_path,
                                entry.header,
                            );
                            log!(
                                args.quiet,
                                "Wrote {} to {}",
                                entry.path.display(),
                                output_path.display()
                            );
                        }
                        EntryKind::Directory => {
                            if output_path.exists() {
                                return;
                            }
                            fs::create_dir_all(&output_path).unwrap();
                            fs::set_permissions(
                                &output_path,
                                Permissions::from_mode(u32::from(entry.header.permissions)),
                            )
                            .unwrap();
                            log!(
                                args.quiet,
                                "Wrote {} to {}",
                                entry.path.display(),
                                output_path.display()
                            );
                        }
                        EntryKind::Symlink(ref e) => {
                            if output_path.exists() {
                                return;
                            }
                            let original_path = e.strip_prefix("/").unwrap_or(e);
                            let _ = unix::fs::symlink(original_path, &output_path);
                            log!(
                                args.quiet,
                                "Wrote {} to {}",
                                entry.path.display(),
                                output_path.display()
                            );
                        }
                        _ => {}
                    };
                } else {
                    log!(args.quiet, "{}", entry.path.display());
                }
            });
        }
        #[cfg(feature = "dwarfs")]
        cli::Commands::DwarfsExtract {
            offset,
            file,
            write,
        } => {
            use squishy::dwarfs::{DwarFS, DwarFSEntryKind};

            let write_path = if let Some(write) = write {
                if let Some(path) = write {
                    fs::create_dir_all(&path).unwrap();
                    Some(path)
                } else {
                    Some(std::env::current_dir().unwrap())
                }
            } else {
                None
            };

            let mut dwarfs = if let Some(offset) = offset {
                DwarFS::from_path_with_offset(&file, offset)
            } else {
                DwarFS::from_path(&file)
            }
            .unwrap_or_else(|e| {
                elog!(args.quiet, "Failed to open DwarFS: {}", e);
                std::process::exit(-1);
            });

            let entries: Vec<_> = dwarfs.entries().collect();

            for entry in &entries {
                if let Some(output_dir) = &write_path {
                    let file_path = entry.path.strip_prefix("/").unwrap_or(&entry.path);
                    let output_path = output_dir.join(file_path);

                    match &entry.kind {
                        DwarFSEntryKind::File => {
                            if output_path.exists() {
                                continue;
                            }
                            fs::create_dir_all(output_path.parent().unwrap()).unwrap();
                            match dwarfs.write_file_with_permissions(entry, &output_path) {
                                Ok(_) => {
                                    log!(
                                        args.quiet,
                                        "Wrote {} to {}",
                                        entry.path.display(),
                                        output_path.display()
                                    );
                                }
                                Err(e) => {
                                    elog!(
                                        args.quiet,
                                        "Failed to write {}: {}",
                                        entry.path.display(),
                                        e
                                    );
                                }
                            }
                        }
                        DwarFSEntryKind::Directory => {
                            if output_path.exists() {
                                continue;
                            }
                            fs::create_dir_all(&output_path).unwrap();
                            fs::set_permissions(&output_path, Permissions::from_mode(entry.mode))
                                .unwrap();
                            log!(
                                args.quiet,
                                "Created dir {} at {}",
                                entry.path.display(),
                                output_path.display()
                            );
                        }
                        DwarFSEntryKind::Symlink(target) => {
                            if output_path.exists() {
                                continue;
                            }
                            fs::create_dir_all(output_path.parent().unwrap()).unwrap();
                            let target_path = target.strip_prefix("/").unwrap_or(target);
                            let _ = unix::fs::symlink(target_path, &output_path);
                            log!(
                                args.quiet,
                                "Linked {} -> {}",
                                entry.path.display(),
                                target.display()
                            );
                        }
                        _ => {}
                    }
                } else {
                    log!(args.quiet, "{}", entry.path.display());
                }
            }
        }
    }
}

fn get_output_filename(
    file_path: &std::path::Path,
    output_name: Option<&std::ffi::OsStr>,
) -> std::ffi::OsString {
    output_name
        .map(|output_name| {
            let name_with_extension = file_path
                .extension()
                .map(|ext| {
                    let file_str = file_path.file_name().unwrap().to_string_lossy();
                    if file_str.ends_with("appdata.xml") || file_str.ends_with("metainfo.xml") {
                        let base_name = if file_str.ends_with("appdata.xml") {
                            "appdata"
                        } else {
                            "metainfo"
                        };
                        format!(
                            "{}.{}.{}",
                            output_name.to_string_lossy(),
                            base_name,
                            ext.to_string_lossy()
                        )
                    } else {
                        format!(
                            "{}.{}",
                            output_name.to_string_lossy(),
                            ext.to_string_lossy()
                        )
                    }
                })
                .unwrap_or_else(|| file_path.file_name().unwrap().to_string_lossy().to_string());

            std::ffi::OsString::from(name_with_extension)
        })
        .unwrap_or_else(|| file_path.file_name().unwrap().to_os_string())
}
