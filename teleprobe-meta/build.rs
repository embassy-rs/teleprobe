use std::path::PathBuf;
use std::{env, fs};

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out.join("teleprobe.x"), include_bytes!("teleprobe.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
}
