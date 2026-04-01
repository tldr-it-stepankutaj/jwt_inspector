#include "jwt_verifier.hpp"
#include "jwt_utils.hpp"

#include <iostream>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>

namespace jwt_inspector {

namespace {

std::string openssl_error_string() {
    unsigned long err = ERR_get_error();
    if (err == 0) return "unknown error";
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return buf;
}

const EVP_MD* md_for_alg(const std::string& alg) {
    if (alg == "RS256" || alg == "ES256") return EVP_sha256();
    if (alg == "RS384" || alg == "ES384") return EVP_sha384();
    if (alg == "RS512" || alg == "ES512") return EVP_sha512();
    return nullptr;
}

// ES256/ES384/ES512 JWT signatures are raw R||S (fixed-size concatenation).
// OpenSSL expects DER-encoded ECDSA_SIG. Convert.
std::vector<uint8_t> raw_ecdsa_to_der(const std::vector<uint8_t>& raw_sig) {
    if (raw_sig.size() % 2 != 0) {
        return {};
    }
    size_t half = raw_sig.size() / 2;

    ECDSA_SIG* ec_sig = ECDSA_SIG_new();
    if (!ec_sig) return {};

    BIGNUM* r = BN_bin2bn(raw_sig.data(), static_cast<int>(half), nullptr);
    BIGNUM* s = BN_bin2bn(raw_sig.data() + half, static_cast<int>(half), nullptr);
    if (!r || !s) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(ec_sig);
        return {};
    }

    // ECDSA_SIG_set0 takes ownership of r and s
    if (ECDSA_SIG_set0(ec_sig, r, s) != 1) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(ec_sig);
        return {};
    }

    int der_len = i2d_ECDSA_SIG(ec_sig, nullptr);
    if (der_len <= 0) {
        ECDSA_SIG_free(ec_sig);
        return {};
    }

    std::vector<uint8_t> der(static_cast<size_t>(der_len));
    uint8_t* p = der.data();
    i2d_ECDSA_SIG(ec_sig, &p);
    ECDSA_SIG_free(ec_sig);
    return der;
}

} // anonymous namespace

VerifyResult verify_token(const std::string& token, const std::string& pubkey_pem,
                          bool json_output) {
    VerifyResult result;

    auto parts = jwt_utils::split_token(token);
    std::string alg = jwt_utils::parse_header_alg(parts.header_b64);
    result.algorithm = alg;

    const EVP_MD* md = md_for_alg(alg);
    if (!md) {
        result.error = "Unsupported algorithm: " + alg;
        if (json_output) {
            std::cout << "{\"valid\":false,\"algorithm\":\"" << alg
                      << "\",\"error\":\"" << result.error << "\"}\n";
        } else {
            std::cerr << "Error: " << result.error << "\n";
        }
        return result;
    }

    // Load public key
    BIO* bio = BIO_new_mem_buf(pubkey_pem.data(), static_cast<int>(pubkey_pem.size()));
    if (!bio) {
        result.error = "Failed to create BIO for public key";
        return result;
    }
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) {
        result.error = "Failed to parse public key: " + openssl_error_string();
        if (json_output) {
            std::cout << "{\"valid\":false,\"algorithm\":\"" << alg
                      << "\",\"error\":\"" << result.error << "\"}\n";
        } else {
            std::cerr << "Error: " << result.error << "\n";
        }
        return result;
    }

    // Decode signature
    auto raw_sig = jwt_utils::base64url_decode(parts.signature_b64);

    // For EC algorithms, convert raw R||S to DER
    std::vector<uint8_t> sig_to_verify;
    bool is_ec = (alg.substr(0, 2) == "ES");
    if (is_ec) {
        sig_to_verify = raw_ecdsa_to_der(raw_sig);
        if (sig_to_verify.empty()) {
            EVP_PKEY_free(pkey);
            result.error = "Failed to convert ECDSA signature to DER format";
            return result;
        }
    } else {
        sig_to_verify = raw_sig;
    }

    // Verify
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        result.error = "Failed to create MD context";
        return result;
    }

    int rc = EVP_DigestVerifyInit(md_ctx, nullptr, md, nullptr, pkey);
    if (rc != 1) {
        result.error = "EVP_DigestVerifyInit failed: " + openssl_error_string();
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return result;
    }

    rc = EVP_DigestVerifyUpdate(md_ctx,
                                 parts.header_payload.data(),
                                 parts.header_payload.size());
    if (rc != 1) {
        result.error = "EVP_DigestVerifyUpdate failed: " + openssl_error_string();
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return result;
    }

    rc = EVP_DigestVerifyFinal(md_ctx, sig_to_verify.data(), sig_to_verify.size());
    result.valid = (rc == 1);

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    if (json_output) {
        std::cout << "{\"valid\":" << (result.valid ? "true" : "false")
                  << ",\"algorithm\":\"" << alg << "\"}\n";
    } else {
        if (result.valid) {
            std::cout << "Signature VALID (" << alg << ")\n";
        } else {
            std::cout << "Signature INVALID (" << alg << ")\n";
        }
    }

    return result;
}

} // namespace jwt_inspector
