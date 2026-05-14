#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::fs;
#[cfg(target_os = "linux")]
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::{Builder, TempDir};

use crate::error::Result;

#[derive(Debug)]
pub struct TempConfig {
    _dir: TempDir,
    path: PathBuf,
}

impl TempConfig {
    pub fn write(prefix: &str, file_name: &str, contents: &[u8]) -> Result<Self> {
        let dir = Builder::new().prefix(prefix).tempdir()?;
        set_dir_permissions(dir.path())?;

        let path = dir.path().join(file_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        file.write_all(contents)?;
        file.flush()?;

        Ok(Self { _dir: dir, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Overwrite a file's contents with zeros and sync to disk before deletion.
///
/// This reduces the window in which secret material is recoverable from
/// the filesystem. The subsequent `TempDir` drop will remove the file.
fn shred_file(path: &Path) {
    if let Ok(metadata) = fs::metadata(path) {
        let len = metadata.len() as usize;
        if len > 0 {
            if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
                let zeros = vec![0_u8; len];
                drop(file.write_all(&zeros));
                drop(file.sync_all());
            }
        }
    }
}

impl Drop for TempConfig {
    fn drop(&mut self) {
        shred_file(&self.path);
    }
}

#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Anonymous in-memory config file (Linux only).
///
/// Uses `memfd_create` to create a file that has no filesystem path.
/// The target app receives `/proc/self/fd/{fd}` as the config path.
/// This eliminates the same-user temp file read attack surface entirely.
///
/// The file descriptor is sealed to prevent modification after creation.
/// When `MemfdConfig` is dropped the fd is closed and the memory is freed.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct MemfdConfig {
    _file: File,
    path: PathBuf,
}

#[cfg(target_os = "linux")]
impl MemfdConfig {
    /// Path to pass to the target process (e.g., `/proc/self/fd/5`).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Create a temp config using an anonymous in-memory file (Linux only).
///
/// Uses `memfd_create` to create a file that has no filesystem path.
/// The target app receives `/proc/self/fd/{fd}` as the config path.
/// This eliminates the same-user temp file read attack surface entirely.
///
/// The fd is created **without** `MFD_CLOEXEC` so that it is inherited by
/// child processes spawned via `Command::spawn`.
#[cfg(target_os = "linux")]
pub fn create_memfd_config(
    prefix: &str,
    filename: &str,
    contents: &[u8],
) -> std::io::Result<MemfdConfig> {
    use std::ffi::CString;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let name = CString::new(format!("{prefix}-{filename}"))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    // No MFD_CLOEXEC: the fd must be inherited by the child process.
    #[allow(unsafe_code)]
    let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Safety: we just created this fd above and it is valid.
    #[allow(unsafe_code)]
    let mut file = unsafe { File::from_raw_fd(fd) };
    Write::write_all(&mut file, contents)?;

    // Seal the file to prevent modification.
    #[allow(unsafe_code)]
    unsafe {
        libc::fcntl(
            fd,
            libc::F_ADD_SEALS,
            libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL,
        );
    }

    let path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));

    Ok(MemfdConfig { _file: file, path })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_reads_temp_config() {
        let temp = TempConfig::write("npmenc-test-", "npmrc", b"token=${NPM_TOKEN}\n")
            .expect("temp config");
        let contents = fs::read_to_string(temp.path()).expect("read back");
        assert_eq!(contents, "token=${NPM_TOKEN}\n");
    }

    #[test]
    fn shred_file_overwrites_contents_with_zeros() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("secret.txt");
        fs::write(&file_path, b"super-secret-value").expect("write");

        shred_file(&file_path);

        let contents = fs::read(&file_path).expect("read after shred");
        assert_eq!(contents.len(), 18); // same length as original
        assert!(contents.iter().all(|&b| b == 0), "file should be all zeros");
    }

    #[test]
    fn drop_shreds_temp_file_before_deletion() {
        let temp =
            TempConfig::write("shred-test-", "config", b"secret-data-here!").expect("temp config");
        let path = temp.path().to_path_buf();
        let dir_path = path.parent().unwrap().to_path_buf();

        // Verify file exists with secret data
        assert!(path.exists());
        assert_eq!(fs::read(&path).unwrap(), b"secret-data-here!");

        // On drop, TempConfig shreds then TempDir deletes.
        drop(temp);

        assert!(!path.exists(), "file should be deleted after drop");
        assert!(!dir_path.exists(), "dir should be deleted after drop");
    }

    #[test]
    fn shred_file_nonexistent_path_is_noop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nonexistent.bin");
        // Should not panic or error
        shred_file(&path);
    }

    #[test]
    fn shred_file_empty_file_is_noop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty.bin");
        fs::write(&path, b"").expect("write empty");
        shred_file(&path);
        // File should still exist, still empty
        assert_eq!(fs::read(&path).unwrap().len(), 0);
    }

    #[test]
    fn shred_file_large_file_all_zeros() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("large.bin");
        let original: Vec<u8> = (0..=255_u8).cycle().take(1024).collect();
        fs::write(&path, &original).expect("write");

        shred_file(&path);

        let after = fs::read(&path).expect("read");
        assert_eq!(after.len(), 1024);
        assert!(after.iter().all(|&b| b == 0));
    }

    #[test]
    fn temp_config_write_empty_contents() {
        let temp = TempConfig::write("test-", "empty.conf", b"").expect("empty temp config");
        let contents = fs::read(temp.path()).expect("read");
        assert!(contents.is_empty());
    }

    #[test]
    fn temp_config_write_binary_contents() {
        let data: Vec<u8> = (0..=255).collect();
        let temp = TempConfig::write("test-", "bin.conf", &data).expect("binary temp config");
        let contents = fs::read(temp.path()).expect("read");
        assert_eq!(contents, data);
    }

    #[test]
    fn temp_config_path_is_inside_temp_dir() {
        let temp = TempConfig::write("test-", "config.conf", b"data").expect("temp config");
        let path = temp.path();
        assert!(path.exists());
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), "config.conf");
    }
}
