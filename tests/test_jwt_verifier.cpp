#include <gtest/gtest.h>
#include "jwt_verifier.hpp"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

namespace {

// Helper: generate an RSA key pair and return PEM strings.
struct RSAKeyPair {
    std::string private_pem;
    std::string public_pem;
};

RSAKeyPair generate_rsa_keypair() {
    RSAKeyPair kp;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    // Private PEM
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    BUF_MEM* buf;
    BIO_get_mem_ptr(bio, &buf);
    kp.private_pem.assign(buf->data, buf->length);
    BIO_free(bio);

    // Public PEM
    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    BIO_get_mem_ptr(bio, &buf);
    kp.public_pem.assign(buf->data, buf->length);
    BIO_free(bio);

    EVP_PKEY_free(pkey);
    return kp;
}

// Helper: base64url encode
std::string b64url_encode(const uint8_t* data, size_t len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data, static_cast<int>(len));
    BIO_flush(b64);
    BUF_MEM* buf;
    BIO_get_mem_ptr(b64, &buf);
    std::string result(buf->data, buf->length);
    BIO_free_all(b64);
    // Convert to URL-safe
    for (auto& c : result) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    result.erase(std::remove(result.begin(), result.end(), '='), result.end());
    return result;
}

// Create a signed RS256 JWT
std::string create_rs256_jwt(const std::string& private_pem) {
    std::string header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"; // {"alg":"RS256","typ":"JWT"}
    std::string payload = "eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjAwMDAwMDAwfQ"; // {"sub":"test","iat":1600000000}
    std::string msg = header + "." + payload;

    // Sign
    BIO* bio = BIO_new_mem_buf(private_pem.data(), static_cast<int>(private_pem.size()));
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestSignUpdate(md_ctx, msg.data(), msg.size());

    size_t sig_len = 0;
    EVP_DigestSignFinal(md_ctx, nullptr, &sig_len);
    std::vector<uint8_t> sig(sig_len);
    EVP_DigestSignFinal(md_ctx, sig.data(), &sig_len);
    sig.resize(sig_len);

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    return msg + "." + b64url_encode(sig.data(), sig.size());
}

} // anonymous namespace

TEST(JWTVerifier, RS256ValidSignature) {
    auto kp = generate_rsa_keypair();
    std::string token = create_rs256_jwt(kp.private_pem);

    auto result = jwt_inspector::verify_token(token, kp.public_pem, true);
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.algorithm, "RS256");
}

TEST(JWTVerifier, RS256TamperedPayload) {
    auto kp = generate_rsa_keypair();
    std::string token = create_rs256_jwt(kp.private_pem);

    // Tamper: change one character in the payload
    size_t first_dot = token.find('.');
    size_t second_dot = token.find('.', first_dot + 1);
    token[first_dot + 1] = (token[first_dot + 1] == 'a') ? 'b' : 'a';

    auto result = jwt_inspector::verify_token(token, kp.public_pem, true);
    EXPECT_FALSE(result.valid);
}

TEST(JWTVerifier, UnsupportedAlgorithm) {
    // HS256 token — verify should report unsupported for HMAC with pubkey verify
    std::string token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

    // This should fail because HS256 is not an RSA/EC algorithm
    auto kp = generate_rsa_keypair();
    auto result = jwt_inspector::verify_token(token, kp.public_pem, true);
    EXPECT_FALSE(result.valid);
}
