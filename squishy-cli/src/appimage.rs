use std::{
    ffi::{OsStr, OsString},
    fs,
    path::Path,
};

use squishy::{error::SquishyError, EntryKind, SquashFS, SquashFSEntry};

pub type Result<T> = std::result::Result<T, SquishyError>;

pub fn extract_file<P: AsRef<Path>>(
    squashfs: &SquashFS,
    entry: &SquashFSEntry,
    output_dir: P,
    output_name: Option<&OsStr>,
    copy_permissions: bool,
) -> Result<()> {
    if let EntryKind::File(squashfs_file) = &entry.kind {
        let file_path = &entry.path;
        let file_name = output_name
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

                OsString::from(name_with_extension)
            })
            .unwrap_or_else(|| file_path.file_name().unwrap().to_os_string());

        fs::create_dir_all(&output_dir)?;
        let output_path = output_dir.as_ref().join(file_name);
        if copy_permissions {
            squashfs.write_file_with_permissions(squashfs_file, &output_path, entry.header)?;
        } else {
            squashfs.write_file(squashfs_file, &output_path)?;
        }
        println!("Wrote {} to {}", file_path.display(), output_path.display());
    }
    Ok(())
}
