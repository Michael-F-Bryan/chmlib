use std::{
    ffi::CString,
    fmt::{self, Debug, Formatter},
    mem::{ManuallyDrop, MaybeUninit},
    os::raw::{c_int, c_void},
    path::Path,
    ptr::NonNull,
};
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
    pub fn find<P: AsRef<Path>>(&mut self, path: P) -> Option<UnitInfo> {
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

    pub fn for_each<F>(&mut self, filter: Filter, mut cb: F)
    where
        F: FnMut(&mut ChmFile, UnitInfo) -> Continuation,
    {
        unsafe {
            chmlib_sys::chm_enumerate(
                self.raw.as_ptr(),
                filter.bits(),
                Some(function_wrapper::<F>),
                &mut cb as *mut _ as *mut c_void,
            );
        }
    }

    pub fn for_each_item_in_dir<F, P>(
        &mut self,
        filter: Filter,
        path: P,
        mut cb: F,
    ) where
        P: AsRef<Path>,
        F: FnMut(&mut ChmFile, UnitInfo) -> Continuation,
    {
        let path = match path_to_cstring(path.as_ref()) {
            Ok(p) => p,
            Err(_) => return,
        };

        unsafe {
            chmlib_sys::chm_enumerate_dir(
                self.raw.as_ptr(),
                path.as_ptr(),
                filter.bits(),
                Some(function_wrapper::<F>),
                &mut cb as *mut _ as *mut c_void,
            );
        }
    }
}

unsafe extern "C" fn function_wrapper<W>(
    file: *mut chmlib_sys::chmFile,
    unit: *mut chmlib_sys::chmUnitInfo,
    state: *mut c_void,
) -> c_int
where
    W: FnMut(&mut ChmFile, UnitInfo) -> Continuation,
{
    // Use ManuallyDrop because we want to give the caller a `&mut ChmFile` but
    // want to make sure the destructor is never called (to prevent
    // double-frees).
    let mut file = ManuallyDrop::new(ChmFile {
        raw: NonNull::new_unchecked(file),
    });
    let unit = UnitInfo::from_raw(unit.read());
    let closure = &mut *(state as *mut W);

    match closure(&mut file, unit) {
        Continuation::Continue => chmlib_sys::CHM_ENUMERATOR_CONTINUE as c_int,
        Continuation::Stop => chmlib_sys::CHM_ENUMERATOR_SUCCESS as c_int,
    }
}

impl Drop for ChmFile {
    fn drop(&mut self) {
        unsafe {
            chmlib_sys::chm_close(self.raw.as_ptr());
        }
    }
}

bitflags::bitflags! {
    pub struct Filter: c_int {
        /// A normal file.
        const NORMAL = chmlib_sys::CHM_ENUMERATE_NORMAL;
        /// A meta file (typically used by the CHM system).
        const META = chmlib_sys::CHM_ENUMERATE_META;
        /// A special file (starts with `#` or `$`).
        const SPECIAL = chmlib_sys::CHM_ENUMERATE_SPECIAL;
        /// It's a file.
        const FILES = chmlib_sys::CHM_ENUMERATE_FILES;
        /// It's a directory.
        const DIRS = chmlib_sys::CHM_ENUMERATE_DIRS;
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Continuation {
    Continue,
    Stop,
}

pub struct UnitInfo {
    pub start: u64,
    pub length: u64,
    pub flags: Filter,
    path: [i8; 513],
}

impl UnitInfo {
    fn from_raw(ui: chmlib_sys::chmUnitInfo) -> UnitInfo {
        let flags = Filter::from_bits_truncate(ui.flags);
        let chmlib_sys::chmUnitInfo {
            start,
            length,
            path,
            ..
        } = ui;

        UnitInfo {
            flags,
            start,
            length,
            path,
        }
    }

    pub fn path(&self) -> Option<&Path> {
        let end = self
            .path
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(self.path.len());

        // we need to cast from c_char* to u8*
        let path = unsafe {
            std::slice::from_raw_parts(self.path.as_ptr() as *const u8, end)
        };

        std::str::from_utf8(path).map(Path::new).ok()
    }
}

impl Debug for UnitInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let path = self.path().unwrap_or(Path::new(""));

        f.debug_struct("UnitInfo")
            .field("start", &self.start)
            .field("length", &self.length)
            .field("flags", &self.flags)
            .field("path", &path)
            .finish()
    }
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
        let mut chm = ChmFile::open(&sample).unwrap();

        assert!(chm.find("/BrowserView.html").is_some());
        assert!(chm.find("doesn't exist.txt").is_none());
    }

    #[test]
    fn iterate_over_items() {
        let sample = sample_path();
        let mut chm = ChmFile::open(&sample).unwrap();

        let mut normal = 0;
        let mut special = 0;
        let mut meta = 0;
        let mut files = 0;
        let mut dirs = 0;

        chm.for_each(Filter::all(), |_chm, unit| {
            if unit.flags.contains(Filter::NORMAL) {
                normal += 1
            }
            if unit.flags.contains(Filter::SPECIAL) {
                special += 1
            }
            if unit.flags.contains(Filter::META) {
                meta += 1
            }
            if unit.flags.contains(Filter::FILES) {
                files += 1
            }
            if unit.flags.contains(Filter::DIRS) {
                dirs += 1
            }

            Continuation::Continue
        });

        assert_eq!(normal, 199);
        assert_eq!(special, 18);
        assert_eq!(meta, 7);
        assert_eq!(files, 179);
        assert_eq!(dirs, 45);
    }
}
