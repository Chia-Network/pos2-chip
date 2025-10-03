fn main() {
    cc::Build::new()
        .cpp(true)
        .std("c++20")
        .warnings_into_errors(true)
        .include("../../src")
        .file("../../src/api.cpp")
        .compile("chiapos_c");
}
