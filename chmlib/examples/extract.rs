use chmlib::{ChmFile, Filter, UnitInfo};
use std::{
    env,
    error::Error,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() != 2 || args.iter().any(|arg| arg.contains("-h")) {
        println!("Usage: extract <chm-file> <out-dir>");
        return;
    }

    let mut file = ChmFile::open(&args[0]).expect("Unable to open the file");

    let out_dir = PathBuf::from(&args[1]);

    file.for_each(Filter::all(), |file, item| extract(&out_dir, file, &item))
        .unwrap();
}

fn extract(
    root_dir: &Path,
    file: &mut ChmFile,
    item: &UnitInfo,
) -> Result<(), Box<dyn Error>> {
    if !item.is_file() || !item.is_normal() {
        // we only care about normal files
        return Ok(());
    }
    let path = match item.path() {
        Some(p) => p,
        // if we can't get the path, ignore it and continue
        None => return Ok(()),
    };

    let mut dest = root_dir.to_path_buf();
    // Note: by design, the path for a normal file is absolute (starts with "/")
    // so when joining it with the root_dir we need to drop the initial "/".
    dest.extend(path.components().skip(1));

    // make sure the parent directory exists
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut f = File::create(dest)?;
    let mut start_offset = 0;
    // CHMLib doesn't give us a &[u8] with the file contents directly (e.g.
    // because it may be compressed) so we need to copy chunks to an
    // intermediate buffer
    let mut buffer = vec![0; 1 << 16];

    loop {
        let bytes_read = file.read(item, start_offset, &mut buffer)?;
        if bytes_read == 0 {
            // we've reached the end of the file
            break;
        } else {
            // write this chunk to the file and continue
            start_offset += bytes_read as u64;
            f.write_all(&buffer)?;
        }
    }

    Ok(())
}
