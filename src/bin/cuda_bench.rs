// CUDA SHA-256d benchmark / verifier for compute-substrate.
//
// Build:   cargo build --release --features cuda --bin cuda_bench
// Run:     ./target/release/cuda_bench [verify|bench [seconds]]
//
// Modes:
//   verify  Generate random headers, hash a range of nonces on GPU,
//           recompute every hash on CPU, assert exact equality.
//   bench   Run the search-style kernel for N seconds (default 30),
//           report achieved hash rate in MH/s and GH/s.
//
// The kernel matches the compute-substrate consensus exactly:
//   - Header serialized as 84 bytes (version LE | prev | merkle | time LE | bits LE | nonce LE)
//   - PoW = sha256(sha256(header))
//   - Compared big-endian against target
//
// Uses raw FFI to libcuda.so (driver API) and libnvrtc.so (runtime
// compilation). No new Rust crate dependencies.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::ptr;
use std::time::{Duration, Instant};

// ============================================================================
// FFI: CUDA Driver API (libcuda.so)
// ============================================================================

type CUresult    = c_int;
type CUdevice    = c_int;
type CUcontext   = *mut c_void;
type CUmodule    = *mut c_void;
type CUfunction  = *mut c_void;
type CUstream    = *mut c_void;
type CUdeviceptr = u64;

#[link(name = "cuda", kind = "dylib")]
extern "C" {
    fn cuInit(flags: c_uint) -> CUresult;
    fn cuDeviceGet(device: *mut CUdevice, ordinal: c_int) -> CUresult;
    fn cuDeviceGetName(name: *mut c_char, len: c_int, dev: CUdevice) -> CUresult;
    fn cuDeviceGetAttribute(pi: *mut c_int, attrib: c_int, dev: CUdevice) -> CUresult;
    fn cuCtxCreate_v2(pctx: *mut CUcontext, flags: c_uint, dev: CUdevice) -> CUresult;
    fn cuCtxDestroy_v2(ctx: CUcontext) -> CUresult;
    fn cuCtxSynchronize() -> CUresult;

    fn cuMemAlloc_v2(dptr: *mut CUdeviceptr, bytesize: usize) -> CUresult;
    fn cuMemFree_v2(dptr: CUdeviceptr) -> CUresult;
    fn cuMemcpyHtoD_v2(dst: CUdeviceptr, src: *const c_void, bytes: usize) -> CUresult;
    fn cuMemcpyDtoH_v2(dst: *mut c_void, src: CUdeviceptr, bytes: usize) -> CUresult;
    fn cuMemsetD8_v2(dptr: CUdeviceptr, uc: u8, n: usize) -> CUresult;

    fn cuModuleLoadData(module: *mut CUmodule, image: *const c_void) -> CUresult;
    fn cuModuleUnload(module: CUmodule) -> CUresult;
    fn cuModuleGetFunction(f: *mut CUfunction, m: CUmodule, name: *const c_char) -> CUresult;

    fn cuLaunchKernel(
        f: CUfunction,
        gx: c_uint, gy: c_uint, gz: c_uint,
        bx: c_uint, by: c_uint, bz: c_uint,
        shared: c_uint,
        stream: CUstream,
        params: *mut *mut c_void,
        extra: *mut *mut c_void,
    ) -> CUresult;

    fn cuGetErrorString(err: CUresult, pstr: *mut *const c_char) -> CUresult;
}

// Device attribute IDs we care about (from cuda.h CUdevice_attribute).
const CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR: c_int = 75;
const CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR: c_int = 76;
const CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT: c_int = 16;

// ============================================================================
// FFI: NVRTC (libnvrtc.so)
// ============================================================================

type nvrtcResult  = c_int;
type nvrtcProgram = *mut c_void;

#[link(name = "nvrtc", kind = "dylib")]
extern "C" {
    fn nvrtcCreateProgram(
        prog: *mut nvrtcProgram,
        src: *const c_char,
        name: *const c_char,
        num_headers: c_int,
        headers: *const *const c_char,
        names: *const *const c_char,
    ) -> nvrtcResult;
    fn nvrtcDestroyProgram(prog: *mut nvrtcProgram) -> nvrtcResult;
    fn nvrtcCompileProgram(
        prog: nvrtcProgram,
        num_opts: c_int,
        opts: *const *const c_char,
    ) -> nvrtcResult;
    fn nvrtcGetPTXSize(prog: nvrtcProgram, size: *mut usize) -> nvrtcResult;
    fn nvrtcGetPTX(prog: nvrtcProgram, ptx: *mut c_char) -> nvrtcResult;
    fn nvrtcGetProgramLogSize(prog: nvrtcProgram, size: *mut usize) -> nvrtcResult;
    fn nvrtcGetProgramLog(prog: nvrtcProgram, log: *mut c_char) -> nvrtcResult;
    fn nvrtcGetErrorString(r: nvrtcResult) -> *const c_char;
}

// ============================================================================
// Error helpers
// ============================================================================

fn cu_check(r: CUresult, ctx: &str) {
    if r == 0 { return; }
    unsafe {
        let mut s: *const c_char = ptr::null();
        let _ = cuGetErrorString(r, &mut s);
        let msg = if s.is_null() {
            "(no error string)".to_string()
        } else {
            CStr::from_ptr(s).to_string_lossy().into_owned()
        };
        panic!("CUDA error in {ctx}: {msg} (code {r})");
    }
}

fn nvrtc_check(r: nvrtcResult, prog: Option<nvrtcProgram>, ctx: &str) {
    if r == 0 { return; }
    unsafe {
        let s = nvrtcGetErrorString(r);
        let msg = if s.is_null() {
            "(no error string)".to_string()
        } else {
            CStr::from_ptr(s).to_string_lossy().into_owned()
        };
        if let Some(p) = prog {
            let mut log_size = 0usize;
            if nvrtcGetProgramLogSize(p, &mut log_size) == 0 && log_size > 1 {
                let mut buf = vec![0u8; log_size];
                if nvrtcGetProgramLog(p, buf.as_mut_ptr() as *mut c_char) == 0 {
                    let log_str = String::from_utf8_lossy(&buf[..log_size.saturating_sub(1)]);
                    eprintln!("--- nvrtc compile log ---\n{log_str}\n-------------------------");
                }
            }
        }
        panic!("NVRTC error in {ctx}: {msg} (code {r})");
    }
}

// ============================================================================
// CPU reference: SHA-256
// ============================================================================

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        let off = i * 4;
        w[i] = u32::from_be_bytes([block[off], block[off+1], block[off+2], block[off+3]]);
    }
    for i in 16..64 {
        let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
        let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
        w[i] = s1.wrapping_add(w[i-7]).wrapping_add(s0).wrapping_add(w[i-16]);
    }
    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
    let (mut e, mut f, mut g, mut h) = (state[4], state[5], state[6], state[7]);
    for i in 0..64 {
        let s1  = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch  = (e & f) ^ ((!e) & g);
        let t1  = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0  = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2  = s0.wrapping_add(maj);
        h = g; g = f; f = e; e = d.wrapping_add(t1);
        d = c; c = b; b = a; a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = H0;
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks_exact(64) {
        let mut blk = [0u8; 64];
        blk.copy_from_slice(chunk);
        sha256_compress(&mut state, &blk);
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i*4..i*4+4].copy_from_slice(&state[i].to_be_bytes());
    }
    out
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// State after processing exactly one 64-byte block from the IV.
fn sha256_midstate(first_block: &[u8; 64]) -> [u32; 8] {
    let mut state = H0;
    sha256_compress(&mut state, first_block);
    state
}

// ============================================================================
// Header
// ============================================================================

#[derive(Clone, Copy, Debug)]
struct Header {
    version: u32,
    prev:    [u8; 32],
    merkle:  [u8; 32],
    time:    u64,
    bits:    u32,
    nonce:   u32,
}

impl Header {
    fn serialize(&self) -> [u8; 84] {
        // Mirrors src/chain/index.rs::header_hash byte layout exactly.
        let mut buf = [0u8; 84];
        buf[0..4].copy_from_slice(&self.version.to_le_bytes());
        buf[4..36].copy_from_slice(&self.prev);
        buf[36..68].copy_from_slice(&self.merkle);
        buf[68..76].copy_from_slice(&self.time.to_le_bytes());
        buf[76..80].copy_from_slice(&self.bits.to_le_bytes());
        buf[80..84].copy_from_slice(&self.nonce.to_le_bytes());
        buf
    }
}

/// (midstate after block 1, first 4 BE-words of block 2)
fn header_to_gpu_params(h: &Header) -> ([u32; 8], [u32; 4]) {
    let buf = h.serialize();
    let mut block1 = [0u8; 64];
    block1.copy_from_slice(&buf[0..64]);
    let midstate = sha256_midstate(&block1);
    let mut pre = [0u32; 4];
    for i in 0..4 {
        let off = 64 + i * 4;
        pre[i] = u32::from_be_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]);
    }
    (midstate, pre)
}

// ============================================================================
// CUDA wrappers (RAII)
// ============================================================================

struct GpuContext {
    ctx: CUcontext,
    sm_count: u32,
    cc_major: u32,
    cc_minor: u32,
}

impl GpuContext {
    fn new() -> Self {
        unsafe {
            cu_check(cuInit(0), "cuInit");
            let mut dev: CUdevice = 0;
            cu_check(cuDeviceGet(&mut dev, 0), "cuDeviceGet");

            let mut name_buf = [0i8; 256];
            cu_check(
                cuDeviceGetName(name_buf.as_mut_ptr() as *mut c_char, 256, dev),
                "cuDeviceGetName",
            );
            let name = CStr::from_ptr(name_buf.as_ptr() as *const c_char).to_string_lossy();

            let mut major: c_int = 0;
            let mut minor: c_int = 0;
            let mut sm: c_int = 0;
            cu_check(cuDeviceGetAttribute(&mut major, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, dev), "cuDeviceGetAttribute(major)");
            cu_check(cuDeviceGetAttribute(&mut minor, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, dev), "cuDeviceGetAttribute(minor)");
            cu_check(cuDeviceGetAttribute(&mut sm, CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT, dev), "cuDeviceGetAttribute(sm_count)");
            println!("[gpu] device 0: {name} (compute capability {major}.{minor}, {sm} SMs)");

            let mut ctx: CUcontext = ptr::null_mut();
            cu_check(cuCtxCreate_v2(&mut ctx, 0, dev), "cuCtxCreate");
            GpuContext {
                ctx,
                sm_count: sm as u32,
                cc_major: major as u32,
                cc_minor: minor as u32,
            }
        }
    }
}

impl Drop for GpuContext {
    fn drop(&mut self) {
        unsafe { let _ = cuCtxDestroy_v2(self.ctx); }
    }
}

fn compile_kernel(src: &str, cc_major: u32, cc_minor: u32) -> Vec<u8> {
    unsafe {
        let src_c = CString::new(src).expect("kernel source must not contain NUL");
        let name_c = CString::new("sha256d_kernel.cu").unwrap();
        let mut prog: nvrtcProgram = ptr::null_mut();
        nvrtc_check(
            nvrtcCreateProgram(&mut prog, src_c.as_ptr(), name_c.as_ptr(), 0, ptr::null(), ptr::null()),
            None,
            "nvrtcCreateProgram",
        );

        let arch_opt = CString::new(format!("--gpu-architecture=sm_{cc_major}{cc_minor}")).unwrap();
        let extra_opt = CString::new("--use_fast_math").unwrap();
        let opts: [*const c_char; 2] = [arch_opt.as_ptr(), extra_opt.as_ptr()];
        let res = nvrtcCompileProgram(prog, opts.len() as c_int, opts.as_ptr());

        // Always print the compile log when non-empty (warnings, info).
        let mut log_size = 0usize;
        let _ = nvrtcGetProgramLogSize(prog, &mut log_size);
        if log_size > 1 {
            let mut buf = vec![0u8; log_size];
            let _ = nvrtcGetProgramLog(prog, buf.as_mut_ptr() as *mut c_char);
            let log_str = String::from_utf8_lossy(&buf[..log_size.saturating_sub(1)]);
            if !log_str.trim().is_empty() {
                eprintln!("[nvrtc log]\n{log_str}");
            }
        }
        nvrtc_check(res, Some(prog), "nvrtcCompileProgram");

        let mut ptx_size = 0usize;
        nvrtc_check(nvrtcGetPTXSize(prog, &mut ptx_size), Some(prog), "nvrtcGetPTXSize");
        let mut ptx = vec![0u8; ptx_size];
        nvrtc_check(nvrtcGetPTX(prog, ptx.as_mut_ptr() as *mut c_char), Some(prog), "nvrtcGetPTX");
        let _ = nvrtcDestroyProgram(&mut prog);
        ptx
    }
}

struct GpuModule {
    module:   CUmodule,
    f_hash:   CUfunction,
    f_search: CUfunction,
    f_bench:  CUfunction,
}

impl GpuModule {
    fn load(ptx: &[u8]) -> Self {
        unsafe {
            let mut module: CUmodule = ptr::null_mut();
            cu_check(
                cuModuleLoadData(&mut module, ptx.as_ptr() as *const c_void),
                "cuModuleLoadData",
            );

            let mut get = |name: &str| -> CUfunction {
                let cname = CString::new(name).unwrap();
                let mut f: CUfunction = ptr::null_mut();
                cu_check(
                    cuModuleGetFunction(&mut f, module, cname.as_ptr()),
                    &format!("cuModuleGetFunction({name})"),
                );
                f
            };
            let f_hash = get("sha256d_hash_only");
            let f_search = get("sha256d_search");
            let f_bench = get("sha256d_bench");
            GpuModule { module, f_hash, f_search, f_bench }
        }
    }
}

impl Drop for GpuModule {
    fn drop(&mut self) {
        unsafe { let _ = cuModuleUnload(self.module); }
    }
}

// Layout must match `struct Params` in the .cu file.
#[repr(C)]
#[derive(Clone, Copy)]
struct Params {
    midstate:          [u32; 8],
    block2_pre:        [u32; 4],
    target:            [u32; 8],
    nonce_base:        u32,
    nonces_per_thread: u32,
}

fn d_alloc(size: usize) -> CUdeviceptr {
    unsafe {
        let mut dptr: CUdeviceptr = 0;
        cu_check(cuMemAlloc_v2(&mut dptr, size), "cuMemAlloc");
        dptr
    }
}

fn d_memset0(dptr: CUdeviceptr, size: usize) {
    unsafe { cu_check(cuMemsetD8_v2(dptr, 0, size), "cuMemsetD8"); }
}

fn h_to_d<T>(dst: CUdeviceptr, src: &T) {
    unsafe {
        cu_check(
            cuMemcpyHtoD_v2(dst, src as *const T as *const c_void, std::mem::size_of::<T>()),
            "cuMemcpyHtoD",
        );
    }
}

fn d_to_h<T: Copy>(dst: &mut [T], src: CUdeviceptr) {
    unsafe {
        cu_check(
            cuMemcpyDtoH_v2(
                dst.as_mut_ptr() as *mut c_void,
                src,
                std::mem::size_of_val(dst),
            ),
            "cuMemcpyDtoH",
        );
    }
}

fn d_free(dptr: CUdeviceptr) {
    unsafe { let _ = cuMemFree_v2(dptr); }
}

unsafe fn launch_2arg(
    f: CUfunction,
    grid_x: u32,
    block_x: u32,
    arg0: &mut CUdeviceptr,
    arg1: &mut CUdeviceptr,
) {
    let mut args: [*mut c_void; 2] = [
        arg0 as *mut _ as *mut c_void,
        arg1 as *mut _ as *mut c_void,
    ];
    cu_check(
        cuLaunchKernel(
            f,
            grid_x, 1, 1,
            block_x, 1, 1,
            0, ptr::null_mut(),
            args.as_mut_ptr(),
            ptr::null_mut(),
        ),
        "cuLaunchKernel",
    );
    cu_check(cuCtxSynchronize(), "cuCtxSynchronize");
}

// ============================================================================
// Mode: verify (self-test)
// ============================================================================

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn mode_verify(module: &GpuModule) {
    use rand::{RngCore, SeedableRng};
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xC0FFEE_C0DE_DEAD);

    const N_HEADERS: usize = 16;
    const N_THREADS_PER_BLOCK: u32 = 256;
    const N_BLOCKS: u32 = 16;
    let n_threads = N_THREADS_PER_BLOCK * N_BLOCKS; // 4096

    println!("[verify] {} headers × {} nonces = {} hashes total", N_HEADERS, n_threads, (N_HEADERS as u32) * n_threads);

    let mut mismatches: u64 = 0;
    let mut total: u64 = 0;

    for hi in 0..N_HEADERS {
        let mut prev = [0u8; 32];
        let mut merkle = [0u8; 32];
        rng.fill_bytes(&mut prev);
        rng.fill_bytes(&mut merkle);
        let header = Header {
            version: rng.next_u32(),
            prev, merkle,
            time: ((rng.next_u32() as u64) << 32) | rng.next_u32() as u64,
            bits: 0x1d00ffff,
            nonce: 0,
        };

        let (midstate, block2_pre) = header_to_gpu_params(&header);
        let nonce_base = rng.next_u32();
        let params = Params {
            midstate, block2_pre,
            target: [0u32; 8],
            nonce_base,
            nonces_per_thread: 1,
        };

        let d_params = d_alloc(std::mem::size_of::<Params>());
        h_to_d(d_params, &params);
        let d_hashes = d_alloc((n_threads as usize) * 8 * 4);

        unsafe {
            let mut a0 = d_params;
            let mut a1 = d_hashes;
            launch_2arg(module.f_hash, N_BLOCKS, N_THREADS_PER_BLOCK, &mut a0, &mut a1);
        }

        let mut gpu_hashes = vec![0u32; (n_threads as usize) * 8];
        d_to_h(&mut gpu_hashes, d_hashes);
        d_free(d_hashes);
        d_free(d_params);

        for tid in 0..n_threads {
            let mut h = header;
            h.nonce = nonce_base.wrapping_add(tid);
            let cpu = sha256d(&h.serialize());

            let mut gpu = [0u8; 32];
            for i in 0..8 {
                let w = gpu_hashes[(tid as usize) * 8 + i];
                gpu[i*4..i*4+4].copy_from_slice(&w.to_be_bytes());
            }

            if cpu != gpu {
                if mismatches < 3 {
                    eprintln!("[verify] MISMATCH header_index={hi} tid={tid} nonce={}", h.nonce);
                    eprintln!("  cpu_hash = 0x{}", hex_encode(&cpu));
                    eprintln!("  gpu_hash = 0x{}", hex_encode(&gpu));
                }
                mismatches += 1;
            }
            total += 1;
        }
    }

    if mismatches == 0 {
        println!("[verify] OK — {total} GPU hashes exactly match CPU reference ✓");
    } else {
        eprintln!("[verify] FAIL — {mismatches} of {total} hashes mismatched ✗");
        std::process::exit(1);
    }
}

// ============================================================================
// Mode: bench
// ============================================================================

fn mode_bench(ctx: &GpuContext, module: &GpuModule, secs: u64) {
    use rand::{RngCore, SeedableRng};
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xDEADBEEF_F00DCAFE);
    let mut prev = [0u8; 32];
    let mut merkle = [0u8; 32];
    rng.fill_bytes(&mut prev);
    rng.fill_bytes(&mut merkle);
    let header = Header {
        version: 1,
        prev, merkle,
        time: 1_700_000_000,
        bits: 0x1d00ffff,
        nonce: 0,
    };
    let (midstate, block2_pre) = header_to_gpu_params(&header);

    // Tuned for Turing (sm_75). 256 threads/block is the sweet spot;
    // sized so each launch saturates the GPU for ~30-100ms.
    const THREADS_PER_BLOCK: u32 = 256;
    const NONCES_PER_THREAD: u32 = 64;
    // Aim for ~8 blocks per SM for occupancy.
    let n_blocks = ctx.sm_count * 32;
    let hashes_per_launch: u64 =
        (THREADS_PER_BLOCK as u64) * (n_blocks as u64) * (NONCES_PER_THREAD as u64);

    println!(
        "[bench] config: {n_blocks} blocks × {THREADS_PER_BLOCK} threads × {NONCES_PER_THREAD} nonces/thread = {} hashes/launch",
        hashes_per_launch
    );
    println!("[bench] running for {secs} seconds…");

    let d_sink = d_alloc(4);
    d_memset0(d_sink, 4);

    // Warmup launch (excluded from timing).
    {
        let warm_params = Params {
            midstate, block2_pre,
            target: [0u32; 8],
            nonce_base: 0,
            nonces_per_thread: NONCES_PER_THREAD,
        };
        let d_params = d_alloc(std::mem::size_of::<Params>());
        h_to_d(d_params, &warm_params);
        unsafe {
            let mut a0 = d_params;
            let mut a1 = d_sink;
            launch_2arg(module.f_bench, n_blocks, THREADS_PER_BLOCK, &mut a0, &mut a1);
        }
        d_free(d_params);
    }

    let start = Instant::now();
    let deadline = start + Duration::from_secs(secs);
    let mut total_hashes: u64 = 0;
    let mut nonce_base: u32 = 0;
    let mut launches: u64 = 0;
    let mut last_report = start;

    while Instant::now() < deadline {
        let params = Params {
            midstate, block2_pre,
            target: [0u32; 8],
            nonce_base,
            nonces_per_thread: NONCES_PER_THREAD,
        };
        let d_params = d_alloc(std::mem::size_of::<Params>());
        h_to_d(d_params, &params);

        unsafe {
            let mut a0 = d_params;
            let mut a1 = d_sink;
            launch_2arg(module.f_bench, n_blocks, THREADS_PER_BLOCK, &mut a0, &mut a1);
        }

        d_free(d_params);
        total_hashes = total_hashes.saturating_add(hashes_per_launch);
        nonce_base = nonce_base.wrapping_add(hashes_per_launch as u32);
        launches += 1;

        let now = Instant::now();
        if now.duration_since(last_report) >= Duration::from_secs(5) {
            let elapsed = now.duration_since(start).as_secs_f64();
            let rate = (total_hashes as f64) / elapsed;
            println!(
                "[bench] @ {:.1}s : {:.0} M hashes done, {:.2} MH/s ({:.3} GH/s)",
                elapsed, total_hashes as f64 / 1e6, rate / 1e6, rate / 1e9
            );
            last_report = now;
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let rate = (total_hashes as f64) / elapsed;

    let mut sink = [0u32; 1];
    d_to_h(&mut sink, d_sink);
    d_free(d_sink);

    println!();
    println!("[bench] ====================================");
    println!("[bench] elapsed:   {elapsed:.3} s");
    println!("[bench] launches:  {launches}");
    println!("[bench] hashes:    {total_hashes}");
    println!("[bench] rate:      {:.2} MH/s", rate / 1e6);
    println!("[bench] rate:      {:.3} GH/s", rate / 1e9);
    println!("[bench] sink:      0x{:08x}  (anti-DCE, should be nonzero)", sink[0]);
    println!("[bench] ====================================");

    // Translate to expected per-block time at network difficulty.
    println!();
    println!("[bench] reference: at network chainwork ~1.1e12 per block,");
    println!("[bench]            expected solo solve interval ≈ {:.1} s",
             1.1e12 / rate);
}

// ============================================================================
// Main
// ============================================================================

const KERNEL_SRC: &str = include_str!("cuda_bench_kernel.cu");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("verify");

    let ctx = GpuContext::new();
    println!("[gpu] compiling kernel with NVRTC for sm_{}{}…", ctx.cc_major, ctx.cc_minor);
    let ptx = compile_kernel(KERNEL_SRC, ctx.cc_major, ctx.cc_minor);
    println!("[gpu] PTX size: {} bytes", ptx.len());
    let module = GpuModule::load(&ptx);
    println!("[gpu] module loaded, kernels resolved ✓");
    println!();

    match mode {
        "verify" | "test" => mode_verify(&module),
        "bench" => {
            let secs: u64 = args.get(2)
                .and_then(|s| s.parse().ok())
                .unwrap_or(30);
            mode_bench(&ctx, &module, secs);
        }
        "both" => {
            mode_verify(&module);
            println!();
            let secs: u64 = args.get(2)
                .and_then(|s| s.parse().ok())
                .unwrap_or(30);
            mode_bench(&ctx, &module, secs);
        }
        _ => {
            eprintln!("usage: cuda_bench [verify | bench [seconds] | both [seconds]]");
            std::process::exit(2);
        }
    }
}
