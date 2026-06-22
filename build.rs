// No-op for default builds. When the `cuda` feature is enabled, emits
// linker flags for libcuda (driver API stub) and libnvrtc.
//
// The driver stub at /opt/cuda/lib64/stubs/libcuda.so is preferred at
// link time so the binary is not tied to a specific installed driver
// version. At runtime, the loader finds the real libcuda.so.1 from
// the installed NVIDIA driver (typically /usr/lib).
fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var_os("CARGO_FEATURE_CUDA").is_some() {
        let cuda_root = std::env::var("CUDA_PATH").unwrap_or_else(|_| "/opt/cuda".to_string());
        println!("cargo:rustc-link-search=native={cuda_root}/lib64/stubs");
        println!("cargo:rustc-link-search=native={cuda_root}/lib64");
        println!("cargo:rustc-link-arg=-Wl,-rpath,{cuda_root}/lib64");
    }
}
