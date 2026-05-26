// 2-way interleaved SHA-NI for the mining hot loop.
//
// PoW is sha256d over the 84-byte header (see chain/index.rs). block1 (bytes
// 0..64) is constant across a nonce sweep, so we absorb it once ("midstate")
// and per nonce only hash block2. block_x2 runs TWO independent hash lanes with
// interleaved sha256rnds2 to hide instruction latency (~1.7x over the sha2
// crate on Zen/SHA-NI). Everything here is validated bit-identical to
// chain::index::header_hash by the tests below — pure speed, zero consensus
// change. On non-SHA-NI CPUs PowMidstate falls back to the sha2 crate.
#![allow(non_snake_case)]

use crate::chain::index::serialize_header;
use crate::types::{BlockHeader, Hash32};
use sha2::{Digest, Sha256};

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[cfg(target_arch = "x86_64")]
fn sha_ni_detected() -> bool {
    use std::sync::OnceLock;
    static C: OnceLock<bool> = OnceLock::new();
    *C.get_or_init(|| {
        is_x86_feature_detected!("sha")
            && is_x86_feature_detected!("sse4.1")
            && is_x86_feature_detected!("ssse3")
    })
}
#[cfg(not(target_arch = "x86_64"))]
fn sha_ni_detected() -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
mod imp {
    use core::arch::x86_64::*;

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    #[inline]
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn kvec(i: usize) -> __m128i {
        _mm_set_epi32(
            K[4 * i + 3] as i32,
            K[4 * i + 2] as i32,
            K[4 * i + 1] as i32,
            K[4 * i] as i32,
        )
    }

    #[inline]
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn loadstate(state: &[u32; 8]) -> (__m128i, __m128i) {
        let tmp = _mm_shuffle_epi32(_mm_loadu_si128(state.as_ptr() as *const __m128i), 0xB1);
        let st1 = _mm_shuffle_epi32(_mm_loadu_si128(state.as_ptr().add(4) as *const __m128i), 0x1B);
        (_mm_alignr_epi8(tmp, st1, 8), _mm_blend_epi16(st1, tmp, 0xF0))
    }

    #[inline]
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn storestate(state: &mut [u32; 8], s0: __m128i, s1: __m128i) {
        let tmp = _mm_shuffle_epi32(s0, 0x1B);
        let s1b = _mm_shuffle_epi32(s1, 0xB1);
        _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, _mm_blend_epi16(tmp, s1b, 0xF0));
        _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, _mm_alignr_epi8(s1b, tmp, 8));
    }

    /// One 64-byte block into `state` (single lane).
    #[inline]
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub unsafe fn block_x1(state: &mut [u32; 8], data: &[u8; 64]) {
        let mask = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);
        let (mut s0, mut s1) = loadstate(state);
        let (abef, cdgh) = (s0, s1);
        let mut m0 = _mm_shuffle_epi8(_mm_loadu_si128(data.as_ptr() as *const __m128i), mask);
        let mut m1 = _mm_shuffle_epi8(_mm_loadu_si128(data.as_ptr().add(16) as *const __m128i), mask);
        let mut m2 = _mm_shuffle_epi8(_mm_loadu_si128(data.as_ptr().add(32) as *const __m128i), mask);
        let mut m3 = _mm_shuffle_epi8(_mm_loadu_si128(data.as_ptr().add(48) as *const __m128i), mask);
        let mut msg = _mm_add_epi32(m0, kvec(0));
        s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
        s0 = _mm_sha256rnds2_epu32(s0, s1, _mm_shuffle_epi32(msg, 0x0E));
        msg = _mm_add_epi32(m1, kvec(1));
        s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
        s0 = _mm_sha256rnds2_epu32(s0, s1, _mm_shuffle_epi32(msg, 0x0E));
        m0 = _mm_sha256msg1_epu32(m0, m1);
        msg = _mm_add_epi32(m2, kvec(2));
        s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
        s0 = _mm_sha256rnds2_epu32(s0, s1, _mm_shuffle_epi32(msg, 0x0E));
        m1 = _mm_sha256msg1_epu32(m1, m2);
        macro_rules! sched {
            ($cur:ident,$prev:ident,$next:ident,$ki:expr,$msg1:expr) => {{
                msg = _mm_add_epi32($cur, kvec($ki));
                s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
                let t = _mm_alignr_epi8($cur, $prev, 4);
                $next = _mm_add_epi32($next, t);
                $next = _mm_sha256msg2_epu32($next, $cur);
                s0 = _mm_sha256rnds2_epu32(s0, s1, _mm_shuffle_epi32(msg, 0x0E));
                if $msg1 {
                    $prev = _mm_sha256msg1_epu32($prev, $cur);
                }
            }};
        }
        sched!(m3, m2, m0, 3, true);
        sched!(m0, m3, m1, 4, true);
        sched!(m1, m0, m2, 5, true);
        sched!(m2, m1, m3, 6, true);
        sched!(m3, m2, m0, 7, true);
        sched!(m0, m3, m1, 8, true);
        sched!(m1, m0, m2, 9, true);
        sched!(m2, m1, m3, 10, true);
        sched!(m3, m2, m0, 11, true);
        sched!(m0, m3, m1, 12, true);
        sched!(m1, m0, m2, 13, false);
        sched!(m2, m1, m3, 14, false);
        msg = _mm_add_epi32(m3, kvec(15));
        s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
        s0 = _mm_sha256rnds2_epu32(s0, s1, _mm_shuffle_epi32(msg, 0x0E));
        s0 = _mm_add_epi32(s0, abef);
        s1 = _mm_add_epi32(s1, cdgh);
        storestate(state, s0, s1);
    }

    /// Two independent 64-byte blocks, instructions interleaved A/B.
    #[inline]
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub unsafe fn block_x2(sa: &mut [u32; 8], da: &[u8; 64], sb: &mut [u32; 8], db: &[u8; 64]) {
        let mask = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);
        let (mut a0, mut a1) = loadstate(sa);
        let (mut b0, mut b1) = loadstate(sb);
        let (xa0, xa1, xb0, xb1) = (a0, a1, b0, b1);
        macro_rules! ld {
            ($p:expr, $o:expr) => {
                _mm_shuffle_epi8(_mm_loadu_si128($p.as_ptr().add($o) as *const __m128i), mask)
            };
        }
        let (mut am0, mut am1, mut am2, mut am3) =
            (ld!(da, 0), ld!(da, 16), ld!(da, 32), ld!(da, 48));
        let (mut bm0, mut bm1, mut bm2, mut bm3) =
            (ld!(db, 0), ld!(db, 16), ld!(db, 32), ld!(db, 48));
        let mut ma;
        let mut mb;
        macro_rules! r0 {
            ($a:ident,$b:ident,$ki:expr) => {{
                ma = _mm_add_epi32($a, kvec($ki));
                mb = _mm_add_epi32($b, kvec($ki));
                a1 = _mm_sha256rnds2_epu32(a1, a0, ma);
                b1 = _mm_sha256rnds2_epu32(b1, b0, mb);
                a0 = _mm_sha256rnds2_epu32(a0, a1, _mm_shuffle_epi32(ma, 0x0E));
                b0 = _mm_sha256rnds2_epu32(b0, b1, _mm_shuffle_epi32(mb, 0x0E));
            }};
        }
        macro_rules! r1 {
            ($a:ident,$b:ident,$am:ident,$bm:ident,$ki:expr) => {{
                r0!($a, $b, $ki);
                $am = _mm_sha256msg1_epu32($am, $a);
                $bm = _mm_sha256msg1_epu32($bm, $b);
            }};
        }
        macro_rules! rs {
            ($ac:ident,$ap:ident,$an:ident,$bc:ident,$bp:ident,$bn:ident,$ki:expr,$m1:expr) => {{
                ma = _mm_add_epi32($ac, kvec($ki));
                mb = _mm_add_epi32($bc, kvec($ki));
                a1 = _mm_sha256rnds2_epu32(a1, a0, ma);
                b1 = _mm_sha256rnds2_epu32(b1, b0, mb);
                let ta = _mm_alignr_epi8($ac, $ap, 4);
                let tb = _mm_alignr_epi8($bc, $bp, 4);
                $an = _mm_add_epi32($an, ta);
                $bn = _mm_add_epi32($bn, tb);
                $an = _mm_sha256msg2_epu32($an, $ac);
                $bn = _mm_sha256msg2_epu32($bn, $bc);
                a0 = _mm_sha256rnds2_epu32(a0, a1, _mm_shuffle_epi32(ma, 0x0E));
                b0 = _mm_sha256rnds2_epu32(b0, b1, _mm_shuffle_epi32(mb, 0x0E));
                if $m1 {
                    $ap = _mm_sha256msg1_epu32($ap, $ac);
                    $bp = _mm_sha256msg1_epu32($bp, $bc);
                }
            }};
        }
        r0!(am0, bm0, 0);
        r1!(am1, bm1, am0, bm0, 1);
        r1!(am2, bm2, am1, bm1, 2);
        rs!(am3, am2, am0, bm3, bm2, bm0, 3, true);
        rs!(am0, am3, am1, bm0, bm3, bm1, 4, true);
        rs!(am1, am0, am2, bm1, bm0, bm2, 5, true);
        rs!(am2, am1, am3, bm2, bm1, bm3, 6, true);
        rs!(am3, am2, am0, bm3, bm2, bm0, 7, true);
        rs!(am0, am3, am1, bm0, bm3, bm1, 8, true);
        rs!(am1, am0, am2, bm1, bm0, bm2, 9, true);
        rs!(am2, am1, am3, bm2, bm1, bm3, 10, true);
        rs!(am3, am2, am0, bm3, bm2, bm0, 11, true);
        rs!(am0, am3, am1, bm0, bm3, bm1, 12, true);
        rs!(am1, am0, am2, bm1, bm0, bm2, 13, false);
        rs!(am2, am1, am3, bm2, bm1, bm3, 14, false);
        r0!(am3, bm3, 15);
        a0 = _mm_add_epi32(a0, xa0);
        a1 = _mm_add_epi32(a1, xa1);
        b0 = _mm_add_epi32(b0, xb0);
        b1 = _mm_add_epi32(b1, xb1);
        storestate(sa, a0, a1);
        storestate(sb, b0, b1);
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn words_to_bytes(s: &[u32; 8]) -> Hash32 {
    let mut o = [0u8; 32];
    for i in 0..8 {
        o[i * 4..i * 4 + 4].copy_from_slice(&s[i].to_be_bytes());
    }
    o
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn second_block(s: &[u32; 8]) -> [u8; 64] {
    let mut h = [0u8; 64];
    for i in 0..8 {
        h[i * 4..i * 4 + 4].copy_from_slice(&s[i].to_be_bytes());
    }
    h[32] = 0x80;
    h[56..64].copy_from_slice(&(256u64).to_be_bytes());
    h
}

/// Cached PoW state for one block template. Hash many nonces cheaply.
pub struct PowMidstate {
    shani: bool,
    #[cfg(target_arch = "x86_64")]
    state: [u32; 8], // block1 absorbed (SHA-NI path)
    b2: [u8; 64],    // second-block template (tail @ [0..20] + padding)
    base: Sha256,    // fallback: sha2 hasher with block1 absorbed
    tail: [u8; 20],
}

impl PowMidstate {
    pub fn new(h: &BlockHeader) -> Self {
        let buf = serialize_header(h);
        let mut b2 = [0u8; 64];
        b2[0..20].copy_from_slice(&buf[64..84]);
        b2[20] = 0x80;
        b2[56..64].copy_from_slice(&(84u64 * 8).to_be_bytes());
        let mut tail = [0u8; 20];
        tail.copy_from_slice(&buf[64..84]);
        let mut base = Sha256::new();
        base.update(&buf[0..64]);

        #[cfg(target_arch = "x86_64")]
        {
            let shani = sha_ni_detected();
            let mut state = H0;
            if shani {
                let mut b1 = [0u8; 64];
                b1.copy_from_slice(&buf[0..64]);
                unsafe { imp::block_x1(&mut state, &b1) };
            }
            PowMidstate { shani, state, b2, base, tail }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            PowMidstate { shani: false, b2, base, tail }
        }
    }

    /// sha256d header hash for one nonce (fallback / single).
    #[inline]
    pub fn hash1(&self, nonce: u32) -> Hash32 {
        let mut h = self.base.clone();
        let mut tail = self.tail;
        tail[16..20].copy_from_slice(&nonce.to_le_bytes());
        h.update(&tail);
        let a = h.finalize();
        Sha256::digest(&a).into()
    }

    /// sha256d header hashes for two nonces. SHA-NI 2-way when available.
    #[inline]
    pub fn hash2(&self, na: u32, nb: u32) -> (Hash32, Hash32) {
        #[cfg(target_arch = "x86_64")]
        {
            if self.shani {
                let mut ba = self.b2;
                let mut bb = self.b2;
                ba[16..20].copy_from_slice(&na.to_le_bytes());
                bb[16..20].copy_from_slice(&nb.to_le_bytes());
                unsafe {
                    let mut sa = self.state;
                    let mut sb = self.state;
                    imp::block_x2(&mut sa, &ba, &mut sb, &bb);
                    let h1a = second_block(&sa);
                    let h1b = second_block(&sb);
                    let mut s2a = H0;
                    let mut s2b = H0;
                    imp::block_x2(&mut s2a, &h1a, &mut s2b, &h1b);
                    return (words_to_bytes(&s2a), words_to_bytes(&s2b));
                }
            }
        }
        (self.hash1(na), self.hash1(nb))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::index::header_hash;

    fn hdr(seed: &mut u64) -> BlockHeader {
        let mut rng = || {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            *seed
        };
        let mut prev = [0u8; 32];
        let mut merkle = [0u8; 32];
        for b in prev.iter_mut() {
            *b = rng() as u8;
        }
        for b in merkle.iter_mut() {
            *b = rng() as u8;
        }
        BlockHeader {
            version: rng() as u32,
            prev,
            merkle,
            time: rng(),
            bits: rng() as u32,
            nonce: 0,
        }
    }

    #[test]
    fn pow_midstate_matches_header_hash() {
        let mut seed = 0x1234_5678_9abc_def0u64;
        for _ in 0..20_000 {
            let mut h = hdr(&mut seed);
            let mid = PowMidstate::new(&h);
            let na = (seed as u32) ^ 0x9e37;
            let nb = na.wrapping_add(0x4141);
            // expected via the canonical consensus hash
            h.nonce = na;
            let ea = header_hash(&h);
            h.nonce = nb;
            let eb = header_hash(&h);
            let (ga, gb) = mid.hash2(na, nb);
            assert_eq!(ga, ea, "hash2 lane A diverged");
            assert_eq!(gb, eb, "hash2 lane B diverged");
            assert_eq!(mid.hash1(na), ea, "hash1 diverged");
        }
    }
}
