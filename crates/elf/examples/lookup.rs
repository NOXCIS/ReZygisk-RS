//! Debug harness: parse an .so from disk, look up symbols exactly the way
//! ptracer's find_func_addr does, and print value/bias next to readelf truth.
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: lookup <file.so> <symbol>...");
        std::process::exit(2);
    }
    let path: PathBuf = args[1].parse().unwrap();
    let raw = std::fs::read(&path).expect("read file");
    let img = rz_elf::ElfImage::parse(&raw).expect("parse elf");

    println!("file      = {}", path.display());
    println!("bias      = {:#x}", img.bias());
    for name in &args[2..] {
        match img.symbol_by_name(name) {
            Some(sym) => println!(
                "symbol {name:<24} value={:#010x} size={:#x} shndx={} info={:#x} other={:#x}",
                sym.value, sym.size, sym.shndx, sym.info, sym.other
            ),
            None => println!("symbol {name:<24} NOT FOUND"),
        }
    }
}
