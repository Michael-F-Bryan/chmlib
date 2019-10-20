use chmlib::{ChmFile, Continuation, Filter, UnitInfo};

use std::{env, path::Path};

fn main() {
    let filename = env::args()
        .nth(1)
        .unwrap_or_else(|| panic!("Usage: enumerate-items <filename>"));

    let mut file = ChmFile::open(&filename).expect("Unable to open the file");

    println!("{}:", filename);
    println!(" spc    start   length   type\t\t\tname");
    println!(" ===    =====   ======   ====\t\t\t====");

    file.for_each(Filter::all(), |_file, item| {
        describe_item(item);
        Continuation::Continue
    });
}

fn describe_item(item: UnitInfo) {
    let mut description = String::new();

    if item.is_normal() {
        description.push_str("normal ");
    } else if item.is_special() {
        description.push_str("special ");
    } else if item.is_meta() {
        description.push_str("meta ");
    }

    if item.is_dir() {
        description.push_str("dir");
    } else if item.is_file() {
        description.push_str("file");
    }

    println!(
        "   {} {:8} {:8}   {}\t\t{}",
        item.space(),
        item.start(),
        item.length(),
        description,
        item.path().unwrap_or(Path::new("")).display()
    );
}
