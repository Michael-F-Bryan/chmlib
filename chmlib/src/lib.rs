use std::{ffi::CString, mem::MaybeUninit, path::Path, ptr::NonNull};
use thiserror::Error;

#[derive(Debug)]
pub struct ChmFile {
    raw: NonNull<chmlib_sys::chmFile>,
}

impl ChmFile {
    /// Open a [`ChmFile`] from the file system.
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

    /// Find a particular object in the archive.
    pub fn find<P: AsRef<Path>>(&self, path: P) -> Option<UnitInfo> {
        let path = path_to_cstring(path.as_ref()).ok()?;

        unsafe {
            // put an uninitialized chmUnitInfo on the stack
            let mut resolved = MaybeUninit::<chmlib_sys::chmUnitInfo>::uninit();

            // then try to resolve the unit info
            let ret = chmlib_sys::chm_resolve_object(
                self.raw.as_ptr(),
                path.as_ptr(),
                resolved.as_mut_ptr(),
            );

            if ret == chmlib_sys::CHM_RESOLVE_SUCCESS as i32 {
                // if successful, "resolved" would have been initialized by C
                Some(UnitInfo::from_raw(resolved.assume_init()))
            } else {
                None
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

#[derive(Debug)]
pub struct UnitInfo;

impl UnitInfo {
    fn from_raw(ui: chmlib_sys::chmUnitInfo) -> UnitInfo { UnitInfo }
}

#[derive(Error, Debug, Copy, Clone, PartialEq)]
#[error("Invalid Path")]
pub struct InvalidPath;

/// The error returned when we are unable to open a [`ChmFile`].
#[derive(Error, Debug, Copy, Clone, PartialEq)]
pub enum OpenError {
    #[error("Invalid path")]
    InvalidPath(#[from] InvalidPath),
    #[error("Unable to open the ChmFile")]
    Other,
}

#[cfg(unix)]
fn path_to_cstring(path: &Path) -> Result<CString, InvalidPath> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    CString::new(bytes).map_err(|_| InvalidPath)
}

#[cfg(not(unix))]
fn path_to_cstring(path: &Path) -> Result<CString, InvalidPath> {
    // Unfortunately, on Windows CHMLib uses CreateFileA() which means all
    // paths will need to be ascii. This can get quite messy, so let's just
    // cross our fingers and hope for the best?
    let rust_str = path.as_os_str().as_str().ok_or(InvalidPath)?;
    CString::new(rust_str).map_err(|_| InvalidPath)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_path() -> PathBuf {
        let project_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let sample = project_dir.parent().unwrap().join("topics.classic.chm");
        assert!(sample.exists());

        sample
    }

    #[test]
    fn open_valid_chm_file() {
        let sample = sample_path();

        // open the file
        let chm_file = ChmFile::open(&sample).unwrap();
        // then immediately close it
        drop(chm_file);
    }

    #[test]
    fn find_an_item_in_the_sample() {
        let sample = sample_path();
        let chm = ChmFile::open(&sample).unwrap();

        assert!(chm.find("/BrowserView.html").is_some());
        assert!(chm.find("doesn't exist.txt").is_none());
    }
}
