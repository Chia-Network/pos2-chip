fn main() {
    println!("cargo:rerun-if-changed=../../src/api.cpp");
    cc::Build::new()
        .cpp(true)
        .std("c++20")
        .flag_if_supported("/EHsc")
        .warnings_into_errors(true)
        .include("cpp")
        .file("cpp/api.cpp")
        .compile("chiapos_c");
}
