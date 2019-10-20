use cc::Build;
use std::{env, path::PathBuf};

fn main() {
    let project_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .canonicalize()
        .unwrap();
    let src = project_dir.join("vendor").join("CHMLib").join("src");

    Build::new()
        .file(src.join("chm_lib.c"))
        .file(src.join("lzx.c"))
        .include(&src)
        .warnings(false)
        .compile("chmlib");
}
