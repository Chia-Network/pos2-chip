fn main() {
    println!("cargo:rerun-if-changed=../../src");

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .std("c++20")
        .flag_if_supported("/EHsc")
        .warnings_into_errors(true)
        .include("cpp")
        .include("fse/fse")
        .file("cpp/api.cpp");

    let is_fuzzing = std::env::var("CARGO_CFG_FUZZING").is_ok();
    let is_debug_build = std::env::var_os("OPT_LEVEL").unwrap_or("".into()) == "0";

    if is_debug_build || is_fuzzing {
        // This enables libc++ hardening
        build.define("_LIBCPP_HARDENING_MODE", "_LIBCPP_HARDENING_MODE_DEBUG");
    }
    build.compile("chiapos_c");

    cc::Build::new()
        .cpp(false)
        .include("fse/fse")
        .file("fse/fse/entropy_common.c")
        .file("fse/fse/fse_compress.c")
        .file("fse/fse/fse_decompress.c")
        .file("fse/fse/fseU16.c")
        .file("fse/fse/huf_compress.c")
        .file("fse/fse/huf_decompress.c")
        .file("fse/fse/hist.c")
        .define("FSE_MAX_MEMORY_USAGE", "16")
        .compile("fse_c");
}
