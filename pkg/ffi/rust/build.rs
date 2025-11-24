// Build script for generating C header bindings
//
// This generates the C header file (bindings.h) that CGO will use
// to interface with the Rust library.

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Generate C bindings using cbindgen
    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::C)
        .with_documentation(true)
        .with_include_guard("ZCASH_T2O_FFI_H")
        .with_style(cbindgen::Style::Both)
        .generate()
        .expect("Unable to generate C bindings")
        .write_to_file("../bindings.h");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/lib.rs");
}
