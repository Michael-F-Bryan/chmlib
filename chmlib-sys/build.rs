use cc::Build;
use std::{env, path::PathBuf};

fn main() {
    let project_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .canonicalize()
        .unwrap();
    let root_dir = project_dir.parent().unwrap();
    let src = root_dir.join("vendor").join("CHMLib").join("src");

    Build::new()
        .file(src.join("chm_lib.c"))
        .file(src.join("lzx.c"))
        .include(&src)
        .warnings(false)
        .compile("chmlib");
}
