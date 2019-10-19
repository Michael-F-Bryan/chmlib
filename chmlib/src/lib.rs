use std::{ffi::CString, path::Path, ptr::NonNull};
use thiserror::Error;

#[derive(Debug)]
pub struct ChmFile {
    raw: NonNull<chmlib_sys::chmFile>,
}

impl ChmFile {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<ChmFile, OpenError> {
        let c_path = path_to_cstring(path.as_ref())?;

        unsafe {
            let raw = chmlib_sys::chm_open(c_path.as_ptr());
            match NonNull::new(raw) {
                Some(raw) => Ok(ChmFile { raw }),
                None => Err(OpenError::Other),
            }
        }
    }
}

impl Drop for ChmFile {
    fn drop(&mut self) {
        unsafe {
            chmlib_sys::chm_close(self.raw.as_ptr());
        }
    }
}

/// The error returned when we are unable to open a [`ChmFile`].
#[derive(Error, Debug, Copy, Clone, PartialEq)]
pub enum OpenError {
    #[error("Invalid path")]
    InvalidPath,
    #[error("Unable to open the ChmFile")]
    Other,
}

#[cfg(unix)]
fn path_to_cstring(path: &Path) -> Result<CString, OpenError> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    CString::new(bytes).map_err(|_| OpenError::InvalidPath)
}

#[cfg(not(unix))]
fn path_to_cstring(path: &Path) -> Result<CString, OpenError> {
    // Unfortunately, on Windows CHMLib uses CreateFileA() which means all
    // paths will need to be ascii. This can get quite messy, so let's just
    // cross our fingers and hope for the best?
    let rust_str = path.as_os_str().as_str().ok_or(OpenError::InvalidPath)?;
    CString::new(rust_str).map_err(|_| OpenError::InvalidPath)
}
