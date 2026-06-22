// SHA-256d (double SHA-256) miner kernel for compute-substrate.
//
// Compiled at runtime via NVRTC. Three entry points:
//   sha256d_hash_only : N threads, each writes its hash. Used by self-test.
//   sha256d_search    : Each thread sweeps a nonce range, first hit wins.
//   sha256d_bench     : Pure throughput; XORs hashes into a sink.
//
// Header layout (84 bytes, see src/chain/index.rs):
//   bytes 0..4   : version u32 LE
//   bytes 4..36  : prev (32 bytes)
//   bytes 36..68 : merkle (32 bytes)
//   bytes 68..76 : time u64 LE
//   bytes 76..80 : bits u32 LE
//   bytes 80..84 : nonce u32 LE  <-- varied per thread
//
// Midstate optimization: the first 64 bytes form SHA-256 block 1 and are
// constant per mining session. Host computes the SHA-256 state after that
// block once and passes it in. Each thread only does block 2 (containing
// nonce) + the second SHA on the 32-byte digest.

typedef unsigned int  uint32_t;

#define ROTR(x, n)    (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)   (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)      (ROTR(x, 2)  ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSIG1(x)      (ROTR(x, 6)  ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSIG0(x)      (ROTR(x, 7)  ^ ROTR(x, 18) ^ ((x) >> 3))
#define SSIG1(x)      (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

__device__ static const uint32_t K_dev[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

__device__ static inline uint32_t bswap32_d(uint32_t x) {
    return ((x & 0x000000ffu) << 24)
         | ((x & 0x0000ff00u) <<  8)
         | ((x & 0x00ff0000u) >>  8)
         | ((x & 0xff000000u) >> 24);
}

__device__ static inline void sha256_compress(uint32_t s[8], const uint32_t Win[16]) {
    uint32_t W[64];
    #pragma unroll
    for (int i = 0; i < 16; i++) W[i] = Win[i];
    #pragma unroll
    for (int i = 16; i < 64; i++) {
        W[i] = SSIG1(W[i-2]) + W[i-7] + SSIG0(W[i-15]) + W[i-16];
    }
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3];
    uint32_t e = s[4], f = s[5], g = s[6], h = s[7];
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        uint32_t T1 = h + BSIG1(e) + CH(e, f, g) + K_dev[i] + W[i];
        uint32_t T2 = BSIG0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d;
    s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

struct Params {
    uint32_t midstate[8];     // SHA-256 state after header block 1 (bytes 0..64)
    uint32_t block2_pre[4];   // Block 2 first 4 words: last 4 merkle bytes, time(lo), time(hi), bits
    uint32_t target[8];       // 32-byte BE target as 8 BE-interpreted u32 words
    uint32_t nonce_base;
    uint32_t nonces_per_thread;
};

// Build the constant parts of block 2's W array.
__device__ static inline void build_W_block2(const Params* p, uint32_t W[16]) {
    W[0]  = p->block2_pre[0];
    W[1]  = p->block2_pre[1];
    W[2]  = p->block2_pre[2];
    W[3]  = p->block2_pre[3];
    // W[4] is the nonce, set per iteration
    W[5]  = 0x80000000u;       // padding: 0x80 byte at offset 84 -> high bit of word 5
    W[6]  = 0;
    W[7]  = 0;
    W[8]  = 0;
    W[9]  = 0;
    W[10] = 0;
    W[11] = 0;
    W[12] = 0;
    W[13] = 0;
    W[14] = 0;
    W[15] = 672u;              // 84 bytes * 8 bits
}

// Compute full SHA-256d for a single nonce given prebuilt params + W block.
__device__ static inline void hash_one(
    const Params* p,
    uint32_t W[16],
    uint32_t nonce,
    uint32_t out_hash[8]
) {
    W[4] = bswap32_d(nonce);

    uint32_t state[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) state[i] = p->midstate[i];
    sha256_compress(state, W);

    // Second SHA over the 32-byte digest.
    uint32_t W2[16] = {
        state[0], state[1], state[2], state[3],
        state[4], state[5], state[6], state[7],
        0x80000000u, 0, 0, 0, 0, 0, 0, 256u
    };
    uint32_t state2[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    sha256_compress(state2, W2);

    #pragma unroll
    for (int i = 0; i < 8; i++) out_hash[i] = state2[i];
}

// hash <= target ?  BE word-by-word.
__device__ static inline bool hash_le_target(const uint32_t hash[8], const uint32_t target[8]) {
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (hash[i] < target[i]) return true;
        if (hash[i] > target[i]) return false;
    }
    return true;  // exactly equal
}

// -------------------------------------------------------------------------
// Self-test kernel: one hash per thread, write to per-thread slot.
// -------------------------------------------------------------------------
extern "C" __global__ void sha256d_hash_only(
    const Params* p,
    uint32_t* out_hashes  // n_threads * 8 u32
) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t nonce = p->nonce_base + tid;

    uint32_t W[16];
    build_W_block2(p, W);

    uint32_t h[8];
    hash_one(p, W, nonce, h);

    #pragma unroll
    for (int i = 0; i < 8; i++) out_hashes[tid * 8u + i] = h[i];
}

// -------------------------------------------------------------------------
// Search kernel: sweep nonce range, first thread to find hash<=target wins.
// -------------------------------------------------------------------------
extern "C" __global__ void sha256d_search(
    const Params* p,
    uint32_t* out_found,    // [0] atomic flag
    uint32_t* out_nonce,    // [0] winning nonce
    uint32_t* out_hash      // [0..8] winning hash (BE u32 words)
) {
    uint32_t tid   = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t base  = p->nonce_base + tid * p->nonces_per_thread;
    uint32_t n_per = p->nonces_per_thread;

    uint32_t W[16];
    build_W_block2(p, W);

    uint32_t tgt[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) tgt[i] = p->target[i];

    for (uint32_t i = 0; i < n_per; i++) {
        // Cheap periodic check for early exit when another thread won.
        if ((i & 0xff) == 0 && i != 0) {
            if (atomicAdd(out_found, 0) != 0) return;
        }

        uint32_t h[8];
        hash_one(p, W, base + i, h);

        if (hash_le_target(h, tgt)) {
            if (atomicCAS(out_found, 0, 1) == 0) {
                *out_nonce = base + i;
                #pragma unroll
                for (int j = 0; j < 8; j++) out_hash[j] = h[j];
            }
            return;
        }
    }
}

// -------------------------------------------------------------------------
// Benchmark kernel: never short-circuits, XORs hashes into sink to defeat
// dead-code elimination. No global writes per hash -> measures raw H/s.
// -------------------------------------------------------------------------
extern "C" __global__ void sha256d_bench(
    const Params* p,
    uint32_t* sink  // single u32, atomically XORed
) {
    uint32_t tid   = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t base  = p->nonce_base + tid * p->nonces_per_thread;
    uint32_t n_per = p->nonces_per_thread;

    uint32_t W[16];
    build_W_block2(p, W);

    uint32_t acc = 0;
    for (uint32_t i = 0; i < n_per; i++) {
        uint32_t h[8];
        hash_one(p, W, base + i, h);
        acc ^= h[0];
    }

    atomicXor(sink, acc);
}
