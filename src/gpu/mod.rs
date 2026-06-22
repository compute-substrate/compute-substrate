//! GPU mining support: SHA-256d on NVIDIA via the CUDA driver API + NVRTC.
//!
//! Compiled only when the `cuda` feature is enabled. See `kernel.cu` for the
//! device-side code. Public API:
//!   - [`enabled_via_env`] — true if `CSD_GPU=1`
//!   - [`ensure_initialized`] — perform global GPU init (idempotent)
//!   - [`with_global`] — run a closure with exclusive access to the miner
//!   - [`header_to_gpu_params`] — prepare midstate + block-2 prefix for a header
//!
//! The single global `GpuMiner` is wrapped in a `Mutex`; mining flows in this
//! repo are single-consumer, but the mutex protects against accidental
//! concurrent access.

#![cfg(feature = "cuda")]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::ptr;
use std::sync::{Mutex, OnceLock};

use crate::types::BlockHeader;

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
    fn cuCtxSetCurrent(ctx: CUcontext) -> CUresult;
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
        shared: c_uint, stream: CUstream,
        params: *mut *mut c_void, extra: *mut *mut c_void,
    ) -> CUresult;
    fn cuGetErrorString(err: CUresult, pstr: *mut *const c_char) -> CUresult;
}

const CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR: c_int = 75;
const CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR: c_int = 76;
const CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT:     c_int = 16;

// ============================================================================
// FFI: NVRTC (libnvrtc.so)
// ============================================================================

type nvrtcResult  = c_int;
type nvrtcProgram = *mut c_void;

#[link(name = "nvrtc", kind = "dylib")]
extern "C" {
    fn nvrtcCreateProgram(
        prog: *mut nvrtcProgram, src: *const c_char, name: *const c_char,
        num_headers: c_int, headers: *const *const c_char, names: *const *const c_char,
    ) -> nvrtcResult;
    fn nvrtcDestroyProgram(prog: *mut nvrtcProgram) -> nvrtcResult;
    fn nvrtcCompileProgram(prog: nvrtcProgram, num_opts: c_int, opts: *const *const c_char) -> nvrtcResult;
    fn nvrtcGetPTXSize(prog: nvrtcProgram, size: *mut usize) -> nvrtcResult;
    fn nvrtcGetPTX(prog: nvrtcProgram, ptx: *mut c_char) -> nvrtcResult;
    fn nvrtcGetProgramLogSize(prog: nvrtcProgram, size: *mut usize) -> nvrtcResult;
    fn nvrtcGetProgramLog(prog: nvrtcProgram, log: *mut c_char) -> nvrtcResult;
    fn nvrtcGetErrorString(r: nvrtcResult) -> *const c_char;
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug)]
pub struct GpuError(pub String);

impl std::fmt::Display for GpuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for GpuError {}

fn cu_err(r: CUresult, ctx: &str) -> Result<(), GpuError> {
    if r == 0 { return Ok(()); }
    unsafe {
        let mut s: *const c_char = ptr::null();
        let _ = cuGetErrorString(r, &mut s);
        let msg = if s.is_null() {
            "(no error string)".to_string()
        } else {
            CStr::from_ptr(s).to_string_lossy().into_owned()
        };
        Err(GpuError(format!("CUDA {ctx}: {msg} (code {r})")))
    }
}

fn nvrtc_err(r: nvrtcResult, prog: Option<nvrtcProgram>, ctx: &str) -> Result<(), GpuError> {
    if r == 0 { return Ok(()); }
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
        Err(GpuError(format!("NVRTC {ctx}: {msg} (code {r})")))
    }
}

// ============================================================================
// Host SHA-256 (for midstate)
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

fn sha256_midstate(first_block: &[u8; 64]) -> [u32; 8] {
    let mut state = H0;
    sha256_compress(&mut state, first_block);
    state
}

/// Convert a `BlockHeader` to (midstate, block2_pre) for the GPU kernel.
/// Mirrors `src/chain/index.rs::header_hash`. The header's `nonce` is ignored.
pub fn header_to_gpu_params(h: &BlockHeader) -> ([u32; 8], [u32; 4]) {
    let mut buf = [0u8; 84];
    buf[0..4].copy_from_slice(&h.version.to_le_bytes());
    buf[4..36].copy_from_slice(&h.prev);
    buf[36..68].copy_from_slice(&h.merkle);
    buf[68..76].copy_from_slice(&h.time.to_le_bytes());
    buf[76..80].copy_from_slice(&h.bits.to_le_bytes());
    buf[80..84].copy_from_slice(&h.nonce.to_le_bytes());

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
// Device-side Params (must match `struct Params` in kernel.cu)
// ============================================================================

#[repr(C)]
struct DeviceParams {
    midstate:          [u32; 8],
    block2_pre:        [u32; 4],
    target:            [u32; 8],
    nonce_base:        u32,
    nonces_per_thread: u32,
}

// ============================================================================
// GpuMiner
// ============================================================================

pub struct GpuMiner {
    ctx:               CUcontext,
    module:            CUmodule,
    f_search:          CUfunction,
    pub sm_count:      u32,
    d_params:          CUdeviceptr,
    d_found:           CUdeviceptr,
    d_nonce:           CUdeviceptr,
    d_hash:            CUdeviceptr,
    pub n_blocks:      u32,
    pub threads_per_block: u32,
}

// CUDA handles are device-managed; we serialize access via a Mutex.
unsafe impl Send for GpuMiner {}
unsafe impl Sync for GpuMiner {}

impl GpuMiner {
    fn try_init() -> Result<Self, GpuError> {
        unsafe {
            cu_err(cuInit(0), "cuInit")?;

            let mut dev: CUdevice = 0;
            cu_err(cuDeviceGet(&mut dev, 0), "cuDeviceGet")?;

            let mut name_buf = [0i8; 256];
            cu_err(
                cuDeviceGetName(name_buf.as_mut_ptr() as *mut c_char, 256, dev),
                "cuDeviceGetName",
            )?;
            let name = CStr::from_ptr(name_buf.as_ptr() as *const c_char)
                .to_string_lossy()
                .into_owned();

            let mut major: c_int = 0;
            let mut minor: c_int = 0;
            let mut sm:    c_int = 0;
            cu_err(cuDeviceGetAttribute(&mut major, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, dev), "attr(major)")?;
            cu_err(cuDeviceGetAttribute(&mut minor, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, dev), "attr(minor)")?;
            cu_err(cuDeviceGetAttribute(&mut sm,    CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT,     dev), "attr(sm)")?;
            println!("[gpu] device 0: {name} (compute capability {major}.{minor}, {sm} SMs)");

            let mut ctx: CUcontext = ptr::null_mut();
            cu_err(cuCtxCreate_v2(&mut ctx, 0, dev), "cuCtxCreate")?;

            println!("[gpu] compiling SHA-256d kernel for sm_{major}{minor}…");
            let kernel_src = include_str!("kernel.cu");
            let src_c = CString::new(kernel_src)
                .map_err(|_| GpuError("kernel source contains NUL".to_string()))?;
            let name_c = CString::new("sha256d_kernel.cu").unwrap();
            let mut prog: nvrtcProgram = ptr::null_mut();
            nvrtc_err(
                nvrtcCreateProgram(&mut prog, src_c.as_ptr(), name_c.as_ptr(), 0, ptr::null(), ptr::null()),
                None,
                "nvrtcCreateProgram",
            )?;

            let arch_opt  = CString::new(format!("--gpu-architecture=sm_{major}{minor}")).unwrap();
            let extra_opt = CString::new("--use_fast_math").unwrap();
            let opts: [*const c_char; 2] = [arch_opt.as_ptr(), extra_opt.as_ptr()];
            let res = nvrtcCompileProgram(prog, opts.len() as c_int, opts.as_ptr());

            let mut log_size = 0usize;
            let _ = nvrtcGetProgramLogSize(prog, &mut log_size);
            if log_size > 1 {
                let mut buf = vec![0u8; log_size];
                let _ = nvrtcGetProgramLog(prog, buf.as_mut_ptr() as *mut c_char);
                let log_str = String::from_utf8_lossy(&buf[..log_size.saturating_sub(1)]);
                if !log_str.trim().is_empty() {
                    eprintln!("[gpu/nvrtc] {}", log_str.trim());
                }
            }
            nvrtc_err(res, Some(prog), "nvrtcCompileProgram")?;

            let mut ptx_size = 0usize;
            nvrtc_err(nvrtcGetPTXSize(prog, &mut ptx_size), Some(prog), "nvrtcGetPTXSize")?;
            let mut ptx = vec![0u8; ptx_size];
            nvrtc_err(
                nvrtcGetPTX(prog, ptx.as_mut_ptr() as *mut c_char),
                Some(prog),
                "nvrtcGetPTX",
            )?;
            let _ = nvrtcDestroyProgram(&mut prog);

            let mut module: CUmodule = ptr::null_mut();
            cu_err(
                cuModuleLoadData(&mut module, ptx.as_ptr() as *const c_void),
                "cuModuleLoadData",
            )?;

            let f_search_name = CString::new("sha256d_search").unwrap();
            let mut f_search: CUfunction = ptr::null_mut();
            cu_err(
                cuModuleGetFunction(&mut f_search, module, f_search_name.as_ptr()),
                "cuModuleGetFunction(sha256d_search)",
            )?;

            let mut d_params: CUdeviceptr = 0;
            let mut d_found:  CUdeviceptr = 0;
            let mut d_nonce:  CUdeviceptr = 0;
            let mut d_hash:   CUdeviceptr = 0;
            cu_err(cuMemAlloc_v2(&mut d_params, std::mem::size_of::<DeviceParams>()), "cuMemAlloc(params)")?;
            cu_err(cuMemAlloc_v2(&mut d_found, 4),  "cuMemAlloc(found)")?;
            cu_err(cuMemAlloc_v2(&mut d_nonce, 4),  "cuMemAlloc(nonce)")?;
            cu_err(cuMemAlloc_v2(&mut d_hash, 32),  "cuMemAlloc(hash)")?;

            // Aim for ~32 blocks per SM; 256 threads/block is the Turing sweet spot.
            let n_blocks = (sm as u32) * 32;
            let threads_per_block: u32 = 256;
            println!(
                "[gpu] miner ready: {} blocks × {} threads = {} threads per launch",
                n_blocks, threads_per_block, n_blocks * threads_per_block,
            );

            Ok(GpuMiner {
                ctx, module, f_search,
                sm_count: sm as u32,
                d_params, d_found, d_nonce, d_hash,
                n_blocks, threads_per_block,
            })
        }
    }

    pub fn n_threads(&self) -> u32 { self.n_blocks * self.threads_per_block }

    pub fn hashes_per_batch(&self, nonces_per_thread: u32) -> u64 {
        (self.n_threads() as u64) * (nonces_per_thread as u64)
    }

    /// Launch one search batch. Returns Some((nonce, hash_be_bytes)) if any
    /// thread found a hash <= target, None otherwise. Total work hashed =
    /// `n_threads * nonces_per_thread`.
    pub fn search_batch(
        &self,
        midstate: &[u32; 8],
        block2_pre: &[u32; 4],
        target_be_bytes: &[u8; 32],
        nonce_base: u32,
        nonces_per_thread: u32,
    ) -> Result<Option<(u32, [u8; 32])>, GpuError> {
        unsafe {
            cu_err(cuCtxSetCurrent(self.ctx), "cuCtxSetCurrent")?;

            let mut target = [0u32; 8];
            for i in 0..8 {
                target[i] = u32::from_be_bytes([
                    target_be_bytes[i*4],     target_be_bytes[i*4+1],
                    target_be_bytes[i*4+2],   target_be_bytes[i*4+3],
                ]);
            }
            let params = DeviceParams {
                midstate:          *midstate,
                block2_pre:        *block2_pre,
                target,
                nonce_base,
                nonces_per_thread,
            };

            cu_err(
                cuMemcpyHtoD_v2(
                    self.d_params,
                    &params as *const _ as *const c_void,
                    std::mem::size_of::<DeviceParams>(),
                ),
                "cuMemcpyHtoD(params)",
            )?;
            cu_err(cuMemsetD8_v2(self.d_found, 0, 4), "cuMemsetD8(found)")?;

            let mut a0 = self.d_params;
            let mut a1 = self.d_found;
            let mut a2 = self.d_nonce;
            let mut a3 = self.d_hash;
            let mut args: [*mut c_void; 4] = [
                &mut a0 as *mut _ as *mut c_void,
                &mut a1 as *mut _ as *mut c_void,
                &mut a2 as *mut _ as *mut c_void,
                &mut a3 as *mut _ as *mut c_void,
            ];
            cu_err(
                cuLaunchKernel(
                    self.f_search,
                    self.n_blocks, 1, 1,
                    self.threads_per_block, 1, 1,
                    0, ptr::null_mut(),
                    args.as_mut_ptr(),
                    ptr::null_mut(),
                ),
                "cuLaunchKernel(search)",
            )?;
            cu_err(cuCtxSynchronize(), "cuCtxSynchronize")?;

            let mut found: u32 = 0;
            cu_err(
                cuMemcpyDtoH_v2(&mut found as *mut _ as *mut c_void, self.d_found, 4),
                "cuMemcpyDtoH(found)",
            )?;
            if found == 0 {
                return Ok(None);
            }

            let mut nonce: u32 = 0;
            cu_err(
                cuMemcpyDtoH_v2(&mut nonce as *mut _ as *mut c_void, self.d_nonce, 4),
                "cuMemcpyDtoH(nonce)",
            )?;
            let mut hash_words = [0u32; 8];
            cu_err(
                cuMemcpyDtoH_v2(hash_words.as_mut_ptr() as *mut c_void, self.d_hash, 32),
                "cuMemcpyDtoH(hash)",
            )?;
            let mut hash = [0u8; 32];
            for i in 0..8 {
                hash[i*4..i*4+4].copy_from_slice(&hash_words[i].to_be_bytes());
            }
            Ok(Some((nonce, hash)))
        }
    }
}

impl Drop for GpuMiner {
    fn drop(&mut self) {
        unsafe {
            let _ = cuCtxSetCurrent(self.ctx);
            let _ = cuMemFree_v2(self.d_params);
            let _ = cuMemFree_v2(self.d_found);
            let _ = cuMemFree_v2(self.d_nonce);
            let _ = cuMemFree_v2(self.d_hash);
            let _ = cuModuleUnload(self.module);
            let _ = cuCtxDestroy_v2(self.ctx);
        }
    }
}

// ============================================================================
// Global lazy miner
// ============================================================================

static GLOBAL_MINER: OnceLock<Mutex<Option<GpuMiner>>> = OnceLock::new();

/// Initialize the global GPU miner. Idempotent — subsequent calls are no-ops
/// and return the cached result.
pub fn ensure_initialized() -> Result<(), GpuError> {
    GLOBAL_MINER.get_or_init(|| {
        match GpuMiner::try_init() {
            Ok(m) => Mutex::new(Some(m)),
            Err(e) => {
                eprintln!("[gpu] init failed: {e}");
                Mutex::new(None)
            }
        }
    });
    let guard = GLOBAL_MINER
        .get()
        .ok_or_else(|| GpuError("OnceLock unexpectedly empty".to_string()))?
        .lock()
        .map_err(|e| GpuError(format!("mutex poisoned: {e}")))?;
    if guard.is_some() {
        Ok(())
    } else {
        Err(GpuError("GPU not available".to_string()))
    }
}

/// Run a closure with exclusive access to the global miner.
/// Returns `None` if the GPU has not been (or could not be) initialized.
pub fn with_global<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&GpuMiner) -> R,
{
    let mutex = GLOBAL_MINER.get()?;
    let guard = mutex.lock().ok()?;
    guard.as_ref().map(f)
}

/// True if `CSD_GPU` env var is set to 1/true/yes/on.
pub fn enabled_via_env() -> bool {
    matches!(
        std::env::var("CSD_GPU")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}
