/// Match `src/CMakeLists.txt` `pos2_base` flags so `intrin_portable.h` sees
/// `__AES__` / `__CRYPTO__` and sets `HAVE_AES`.
fn apply_hw_aes_flags(build: &mut cc::Build) {
    let Ok(arch) = std::env::var("CARGO_CFG_TARGET_ARCH") else {
        return;
    };
    let target = std::env::var("TARGET").unwrap_or_default();
    let is_msvc = target.contains("msvc");

    match arch.as_str() {
        // x86_64: GCC/Clang need `-maes` (CMake: GNU|Clang only). MSVC gets AES via intrin_portable.h.
        "x86_64" if !is_msvc => {
            build.flag_if_supported("-maes");
        }
        // 64-bit ARM: enable crypto extensions (e.g. Raspberry Pi 5).
        "aarch64" => {
            build.flag_if_supported("-march=armv8-a+crypto");
        }
        _ => {}
    }
}

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
    apply_hw_aes_flags(&mut build);

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
