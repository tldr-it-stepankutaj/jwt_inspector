// Correct HMAC-SHA256 implementation for GPU bruteforce.
// Supports multi-block SHA-256 (arbitrary input length).

__constant uint K[64] = {
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
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint rotr(uint x, uint n) {
    return (x >> n) | (x << (32 - n));
}

void sha256_transform(__private const uchar *block, __private uint *state) {
    uint w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint)block[i * 4] << 24) |
               ((uint)block[i * 4 + 1] << 16) |
               ((uint)block[i * 4 + 2] << 8) |
               ((uint)block[i * 4 + 3]);
    }

    for (int i = 16; i < 64; ++i) {
        uint s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint a = state[0], b = state[1], c = state[2], d = state[3];
    uint e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; ++i) {
        uint S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint ch = (e & f) ^ ((~e) & g);
        uint temp1 = h + S1 + ch + K[i] + w[i];
        uint S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// Multi-block SHA-256: handles arbitrary input length.
void sha256(__private const uchar *data, uint len, __private uint *hash) {
    // Initialize state
    hash[0] = 0x6a09e667; hash[1] = 0xbb67ae85;
    hash[2] = 0x3c6ef372; hash[3] = 0xa54ff53a;
    hash[4] = 0x510e527f; hash[5] = 0x9b05688c;
    hash[6] = 0x1f83d9ab; hash[7] = 0x5be0cd19;

    // Process complete 64-byte blocks
    uint offset = 0;
    while (offset + 64 <= len) {
        sha256_transform(data + offset, hash);
        offset += 64;
    }

    // Final block(s) with padding
    uchar block[64];
    uint remaining = len - offset;
    for (uint i = 0; i < remaining; ++i) {
        block[i] = data[offset + i];
    }
    block[remaining] = 0x80;
    for (uint i = remaining + 1; i < 64; ++i) {
        block[i] = 0;
    }

    // If there isn't room for the 8-byte length, we need an extra block
    if (remaining >= 56) {
        sha256_transform(block, hash);
        for (int i = 0; i < 64; ++i) {
            block[i] = 0;
        }
    }

    // Append bit length as big-endian 64-bit (we only use 32 bits since len < 2^32)
    uint bitlen = len * 8;
    block[56] = 0;
    block[57] = 0;
    block[58] = 0;
    block[59] = 0;
    block[60] = (bitlen >> 24) & 0xFF;
    block[61] = (bitlen >> 16) & 0xFF;
    block[62] = (bitlen >> 8) & 0xFF;
    block[63] = bitlen & 0xFF;
    sha256_transform(block, hash);
}

// Serialize uint[8] hash state to big-endian bytes
void hash_to_bytes(__private const uint *hash, __private uchar *out) {
    for (int i = 0; i < 8; ++i) {
        out[i * 4 + 0] = (hash[i] >> 24) & 0xFF;
        out[i * 4 + 1] = (hash[i] >> 16) & 0xFF;
        out[i * 4 + 2] = (hash[i] >> 8) & 0xFF;
        out[i * 4 + 3] = hash[i] & 0xFF;
    }
}

// MAX_MSG_LEN: maximum header.payload length supported.
// Total inner input = 64 (ipad) + header_len, must fit in inner_data array.
#define MAX_MSG_LEN 512

__kernel void hmac_sha256_bruteforce(
    __global const uchar *header_payload,
    const int header_len,
    __global const uchar *secrets,
    const int max_secret_len,
    __global const int *secret_lengths,
    const int total_words,
    __global const uchar *expected_sig,
    __global volatile int *found_index
) {
    int gid = get_global_id(0);
    if (gid >= total_words) return;
    if (*found_index >= 0) return;

    __global const uchar *secret = secrets + gid * max_secret_len;
    int key_len = secret_lengths[gid];

    // HMAC-SHA256:
    //   inner = SHA256( (key XOR ipad) || message )
    //   outer = SHA256( (key XOR opad) || inner_hash )
    // ipad/opad are always 64 bytes.

    // Build ipad and opad (64 bytes each)
    uchar i_key_pad[64];
    uchar o_key_pad[64];
    for (int i = 0; i < 64; ++i) {
        i_key_pad[i] = 0x36;
        o_key_pad[i] = 0x5c;
    }
    for (int i = 0; i < key_len && i < 64; ++i) {
        i_key_pad[i] ^= secret[i];
        o_key_pad[i] ^= secret[i];
    }

    // Inner: SHA256(i_key_pad[64] || header_payload[header_len])
    uchar inner_data[64 + MAX_MSG_LEN];
    for (int i = 0; i < 64; ++i) {
        inner_data[i] = i_key_pad[i];
    }
    for (int i = 0; i < header_len && i < MAX_MSG_LEN; ++i) {
        inner_data[64 + i] = header_payload[i];
    }

    uint inner_hash[8];
    sha256(inner_data, 64 + header_len, inner_hash);

    // Serialize inner hash to bytes (big-endian)
    uchar inner_hash_bytes[32];
    hash_to_bytes(inner_hash, inner_hash_bytes);

    // Outer: SHA256(o_key_pad[64] || inner_hash_bytes[32])
    uchar outer_data[96];  // always 64 + 32 = 96
    for (int i = 0; i < 64; ++i) {
        outer_data[i] = o_key_pad[i];
    }
    for (int i = 0; i < 32; ++i) {
        outer_data[64 + i] = inner_hash_bytes[i];
    }

    uint final_hash[8];
    sha256(outer_data, 96, final_hash);

    // Serialize and compare with expected signature
    uchar final_bytes[32];
    hash_to_bytes(final_hash, final_bytes);

    for (int i = 0; i < 32; ++i) {
        if (final_bytes[i] != expected_sig[i]) return;
    }

    // Atomic write: only first finder wins
    atomic_cmpxchg(found_index, -1, gid);
}
