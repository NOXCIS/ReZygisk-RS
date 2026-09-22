//! Debug harness: print the relocations exactly as ptracer's apply_relocations
//! iterates them, for diffing against llvm-readelf -r.
fn main() {
    let path = std::env::args().nth(1).expect("usage: relocs <file.so>");
    let raw = std::fs::read(&path).expect("read file");
    let img = rz_elf::ElfImage::parse(&raw).expect("parse elf");

    let relocs = match img.relocations() {
        Ok(relocs) => relocs,
        Err(e) => {
            eprintln!("failed to decode relocations: {e}");
            std::process::exit(1);
        }
    };
    println!("total = {}", relocs.len());
    for rel in relocs {
        println!(
            "{:#x} {:#x} sym={:#x}{}",
            rel.offset,
            rel.rtype, rel.sym_idx,
            if rel.has_addend {
                format!(" addend={}", rel.addend as i64)
            } else {
                String::new()
            }
        );
    }
}
