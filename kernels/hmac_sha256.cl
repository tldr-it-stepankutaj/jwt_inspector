// Simplified SHA256 and HMAC-SHA256 implementation for brute-force JWT
// Adapted for OpenCL (based on public domain sources)

__constant uint k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

uint rotr(uint x, uint n) {
    return (x >> n) | (x << (32 - n));
}

void sha256_transform(const uchar *data, uint *state) {
    uint w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) | (data[i * 4 + 2] << 8) | data[i * 4 + 3];
    }

    for (int i = 16; i < 64; ++i) {
        uint s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint a = state[0];
    uint b = state[1];
    uint c = state[2];
    uint d = state[3];
    uint e = state[4];
    uint f = state[5];
    uint g = state[6];
    uint h = state[7];

    for (int i = 0; i < 64; ++i) {
        uint S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint ch = (e & f) ^ ((~e) & g);
        uint temp1 = h + S1 + ch + k[i] + w[i];
        uint S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256(const uchar *data, int len, uint *hash) {
    uchar block[64] = {0};
    for (int i = 0; i < len; ++i) {
        block[i] = data[i];
    }
    block[len] = 0x80;
    uint bitlen = len * 8;
    block[63] = bitlen & 0xFF;
    block[62] = (bitlen >> 8) & 0xFF;
    block[61] = (bitlen >> 16) & 0xFF;
    block[60] = (bitlen >> 24) & 0xFF;

    hash[0] = 0x6a09e667;
    hash[1] = 0xbb67ae85;
    hash[2] = 0x3c6ef372;
    hash[3] = 0xa54ff53a;
    hash[4] = 0x510e527f;
    hash[5] = 0x9b05688c;
    hash[6] = 0x1f83d9ab;
    hash[7] = 0x5be0cd19;

    sha256_transform(block, hash);
}

__kernel void hmac_sha256_bruteforce(
    __global const uchar *header_payload,
    const int header_len,
    __global const uchar *secrets,
    const int secret_len,
    const int total_words,
    __global const uchar *expected_sig,
    __global int *found_index
) {
    int gid = get_global_id(0);
    if (gid >= total_words || *found_index >= 0) return;

    __global const uchar *secret = secrets + gid * secret_len;

    // Compose message: HMAC = sha256((key XOR ipad) + message)
    uchar block[64] = {0};
    uchar o_key_pad[64] = {0x5c};
    uchar i_key_pad[64] = {0x36};

    for (int i = 0; i < secret_len; i++) {
        i_key_pad[i] ^= secret[i];
        o_key_pad[i] ^= secret[i];
    }

    for (int i = 0; i < header_len; i++) {
        block[secret_len + i] = header_payload[i];
    }

    uchar inner[64] = {0};
    for (int i = 0; i < 64; i++) block[i] = 0;
    for (int i = 0; i < secret_len; i++) block[i] = i_key_pad[i];
    for (int i = 0; i < header_len; i++) block[secret_len + i] = header_payload[i];

    uint inner_hash[8];
    sha256(block, secret_len + header_len, inner_hash);

    uchar outer_block[64] = {0};
    for (int i = 0; i < 64; i++) outer_block[i] = 0;
    for (int i = 0; i < secret_len; i++) outer_block[i] = o_key_pad[i];
    for (int i = 0; i < 32; i++) outer_block[secret_len + i] = ((uchar*)&inner_hash)[i];

    uint final_hash[8];
    sha256(outer_block, secret_len + 32, final_hash);

    // Compare with expected
    for (int i = 0; i < 32; ++i) {
        if (((uchar*)final_hash)[i] != expected_sig[i]) return;
    }

    *found_index = gid;
}