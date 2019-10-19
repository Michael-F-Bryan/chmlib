// we need to convert the Path to a char* with trailing NULL. Unfortunately on
// Windows OsStr (and therefore Path) is a [u16] under the hood and can't be
// properly passed in as a char* string.
#![cfg(unix)]

use std::{ffi::CString, os::unix::ffi::OsStrExt, path::Path};

#[test]
fn open_example_file() {
    let project_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sample_chm = project_dir.parent().unwrap().join("topics.classic.chm");
    let c_str = CString::new(sample_chm.as_os_str().as_bytes()).unwrap();

    unsafe {
        let handle = chmlib_sys::chm_open(c_str.as_ptr());
        assert!(!handle.is_null());
        chmlib_sys::chm_close(handle);
    }
}
