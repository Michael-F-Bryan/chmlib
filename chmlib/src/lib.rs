use std::{
    any::Any,
    error::Error,
    ffi::CString,
    fmt::{self, Debug, Formatter},
    mem::{ManuallyDrop, MaybeUninit},
    os::raw::{c_int, c_void},
    panic,
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

    /// Inspect each item within the [`ChmFile`].
    pub fn for_each<F, C>(
        &mut self,
        filter: Filter,
        cb: F,
    ) -> Result<(), EnumerationError>
    where
        F: FnMut(&mut ChmFile, UnitInfo) -> C,
        C: Into<Continuation>,
    {
        unsafe {
            let mut state = WrapperState::new(cb);
            let ret = chmlib_sys::chm_enumerate(
                self.raw.as_ptr(),
                filter.bits(),
                Some(function_wrapper::<F, C>),
                &mut state as *mut _ as *mut c_void,
            );
            handle_enumeration_result(state, ret)
        }
    }

    /// Inspect each item within the [`ChmFile`] inside a specified directory.
    pub fn for_each_item_in_dir<F, C, P>(
        &mut self,
        filter: Filter,
        prefix: P,
        cb: F,
    ) -> Result<(), EnumerationError>
    where
        P: AsRef<Path>,
        F: FnMut(&mut ChmFile, UnitInfo) -> C,
        C: Into<Continuation>,
    {
        let path = path_to_cstring(prefix.as_ref())
            .map_err(EnumerationError::InvalidPrefix)?;

        unsafe {
            let mut state = WrapperState::new(cb);
            let ret = chmlib_sys::chm_enumerate_dir(
                self.raw.as_ptr(),
                path.as_ptr(),
                filter.bits(),
                Some(function_wrapper::<F, C>),
                &mut state as *mut _ as *mut c_void,
            );
            handle_enumeration_result(state, ret)
        }
    }

    pub fn read(
        &mut self,
        unit: &UnitInfo,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, ReadError> {
        let mut unit = unit.0.clone();

        let bytes_written = unsafe {
            chmlib_sys::chm_retrieve_object(
                self.raw.as_ptr(),
                &mut unit,
                buffer.as_mut_ptr(),
                offset,
                buffer.len() as _,
            )
        };

        if bytes_written >= 0 {
            Ok(bytes_written as usize)
        } else {
            Err(ReadError)
        }
    }
}

fn handle_enumeration_result<F>(
    state: WrapperState<F>,
    ret: c_int,
) -> Result<(), EnumerationError> {
    if let Some(panic) = state.panic {
        panic::resume_unwind(panic)
    } else if let Some(err) = state.error {
        Err(EnumerationError::User(err))
    } else if ret < 0 {
        Err(EnumerationError::Internal)
    } else {
        Ok(())
    }
}

struct WrapperState<F> {
    closure: F,
    error: Option<Box<dyn Error + 'static>>,
    panic: Option<Box<dyn Any + Send + 'static>>,
}

impl<F> WrapperState<F> {
    fn new(closure: F) -> WrapperState<F> {
        WrapperState {
            closure,
            error: None,
            panic: None,
        }
    }
}

unsafe extern "C" fn function_wrapper<F, C>(
    file: *mut chmlib_sys::chmFile,
    unit: *mut chmlib_sys::chmUnitInfo,
    state: *mut c_void,
) -> c_int
where
    F: FnMut(&mut ChmFile, UnitInfo) -> C,
    C: Into<Continuation>,
{
    // we need to make sure panics can't escape across the FFI boundary.
    let result = panic::catch_unwind(|| {
        // Use ManuallyDrop because we want to give the caller a `&mut ChmFile`
        // but want to make sure the destructor is never called (to
        // prevent double-frees).
        let mut file = ManuallyDrop::new(ChmFile {
            raw: NonNull::new_unchecked(file),
        });
        let unit = UnitInfo::from_raw(unit.read());
        // the opaque state pointer is guaranteed to point to an instance of our
        // closure
        let state = &mut *(state as *mut WrapperState<F>);
        (state.closure)(&mut file, unit)
    });

    let mut state = &mut *(state as *mut WrapperState<F>);

    match result.map(Into::into) {
        Ok(Continuation::Continue) => {
            chmlib_sys::CHM_ENUMERATOR_CONTINUE as c_int
        },
        Ok(Continuation::Failure(err)) => {
            state.error = Some(err);
            chmlib_sys::CHM_ENUMERATOR_FAILURE as c_int
        },
        Ok(Continuation::Stop) => chmlib_sys::CHM_ENUMERATOR_SUCCESS as c_int,
        Err(panic) => {
            state.panic = Some(panic);
            chmlib_sys::CHM_ENUMERATOR_FAILURE as c_int
        },
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
        const NORMAL = chmlib_sys::CHM_ENUMERATE_NORMAL as c_int;
        /// A meta file (typically used by the CHM system).
        const META = chmlib_sys::CHM_ENUMERATE_META as c_int;
        /// A special file (starts with `#` or `$`).
        const SPECIAL = chmlib_sys::CHM_ENUMERATE_SPECIAL as c_int;
        /// It's a file.
        const FILES = chmlib_sys::CHM_ENUMERATE_FILES as c_int;
        /// It's a directory.
        const DIRS = chmlib_sys::CHM_ENUMERATE_DIRS as c_int;
    }
}

pub enum Continuation {
    /// Continue iterating over items.
    Continue,
    /// Stop iterating and bail with an error.
    Failure(Box<dyn Error + 'static>),
    /// Stop iterating without returning an error (e.g. iteration finished
    /// successfully).
    Stop,
}

impl From<()> for Continuation {
    fn from(_: ()) -> Continuation { Continuation::Continue }
}

impl<E: Into<Box<dyn Error + 'static>>> From<Result<(), E>> for Continuation {
    fn from(other: Result<(), E>) -> Continuation {
        match other {
            Ok(_) => Continuation::Continue,
            Err(e) => Continuation::Failure(e.into()),
        }
    }
}

#[repr(transparent)]
pub struct UnitInfo(chmlib_sys::chmUnitInfo);

impl UnitInfo {
    fn from_raw(ui: chmlib_sys::chmUnitInfo) -> UnitInfo { UnitInfo(ui) }

    fn flags(&self) -> Filter { Filter::from_bits_truncate(self.0.flags) }

    pub fn is_normal(&self) -> bool { self.flags().contains(Filter::NORMAL) }

    pub fn is_special(&self) -> bool { self.flags().contains(Filter::SPECIAL) }

    pub fn is_meta(&self) -> bool { self.flags().contains(Filter::META) }

    pub fn is_file(&self) -> bool { self.flags().contains(Filter::FILES) }

    pub fn is_dir(&self) -> bool { self.flags().contains(Filter::DIRS) }

    pub fn space(&self) -> c_int { self.0.space }

    /// The starting position within the underlying file.
    pub fn start(&self) -> u64 { self.0.start }

    /// The number of bytes in this item.
    pub fn length(&self) -> u64 { self.0.length }

    /// The item's filename.
    ///
    /// # Security
    ///
    /// This path is provided by the original CHM file's author. It is the
    /// caller's responsibility to handle malicious input (e.g.
    /// `/../../../etc/passwd`).
    pub fn path(&self) -> Option<&Path> {
        let end = self
            .0
            .path
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(self.0.path.len());

        // we need to cast from c_char* to u8*
        let path = unsafe {
            std::slice::from_raw_parts(self.0.path.as_ptr() as *const u8, end)
        };

        std::str::from_utf8(path).map(Path::new).ok()
    }
}

impl Debug for UnitInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let path = self.path().unwrap_or(Path::new(""));

        f.debug_struct("UnitInfo")
            .field("start", &self.0.start)
            .field("length", &self.0.length)
            .field("flags", &self.0.flags)
            .field("space", &self.0.space)
            .field("path", &path)
            .finish()
    }
}

#[derive(Error, Debug, Copy, Clone, PartialEq)]
#[error("Invalid Path")]
pub struct InvalidPath;

#[derive(Error, Debug)]
pub enum EnumerationError {
    /// A user-provided error.
    #[error("An error was encountered while iterating")]
    User(#[source] Box<dyn Error + 'static>),
    #[error("The prefix was invalid")]
    InvalidPrefix(#[source] InvalidPath),
    #[error("CHMLib returned an error")]
    Internal,
}

#[derive(Error, Debug, Copy, Clone, PartialEq)]
#[error("The read failed")]
pub struct ReadError;

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
            if unit.flags().contains(Filter::NORMAL) {
                normal += 1
            }
            if unit.flags().contains(Filter::SPECIAL) {
                special += 1
            }
            if unit.flags().contains(Filter::META) {
                meta += 1
            }
            if unit.flags().contains(Filter::FILES) {
                files += 1
            }
            if unit.flags().contains(Filter::DIRS) {
                dirs += 1
            }

            Continuation::Continue
        })
        .unwrap();

        assert_eq!(normal, 199);
        assert_eq!(special, 18);
        assert_eq!(meta, 7);
        assert_eq!(files, 179);
        assert_eq!(dirs, 45);
    }

    #[test]
    fn read_an_item() {
        let sample = sample_path();
        let mut chm = ChmFile::open(&sample).unwrap();
        let filename = "/template/packages/core-web/css/index.responsive.css";

        // look for a known file
        let item = chm.find(filename).unwrap();

        // then read it into a buffer
        let mut buffer = vec![0; item.length() as usize];
        let bytes_written = chm.read(&item, 0, &mut buffer).unwrap();

        // we should have read everything
        assert_eq!(bytes_written, item.length() as usize);

        // ... and got what we expected
        let got = String::from_utf8(buffer).unwrap();
        assert!(got.starts_with(
            "html, body, div#i-index-container, div#i-index-body"
        ));
    }

    #[test]
    fn continuation_with_unit() {
        let sample = sample_path();
        let mut chm = ChmFile::open(&sample).unwrap();

        chm.for_each(Filter::all(), |_, _| {}).unwrap();
    }

    #[test]
    fn continuation_with_result() {
        let sample = sample_path();
        let mut chm = ChmFile::open(&sample).unwrap();

        let got_err = chm
            .for_each(Filter::all(), |_, _| Err(InvalidPath))
            .unwrap_err();

        match got_err {
            EnumerationError::User(err) => {
                assert!(err.downcast_ref::<InvalidPath>().is_some())
            },
            _ => panic!("Unexpected error: {}", got_err),
        }
    }

    #[test]
    #[should_panic(expected = "Oops...")]
    fn panics_are_propagated() {
        let sample = sample_path();
        let mut chm = ChmFile::open(&sample).unwrap();

        chm.for_each(Filter::all(), |_, _| panic!("Oops..."))
            .unwrap();
    }
}
