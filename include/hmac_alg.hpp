#pragma once

#include <string>

#include <openssl/evp.h>

namespace jwt_inspector {

/// Maps an HMAC JWT "alg" value (HS256/HS384/HS512) to the matching OpenSSL digest.
/// Returns nullptr for anything else (including RS*/ES*, which are asymmetric and
/// handled by jwt_verifier, not by HMAC-based bruteforce/forge code).
inline const EVP_MD* hmac_md_for_alg(const std::string& alg) {
    if (alg == "HS256") return EVP_sha256();
    if (alg == "HS384") return EVP_sha384();
    if (alg == "HS512") return EVP_sha512();
    return nullptr;
}

/// Digest size in bytes for an HMAC JWT "alg" value, or 0 if unknown.
inline size_t hmac_digest_size_for_alg(const std::string& alg) {
    if (alg == "HS256") return 32;
    if (alg == "HS384") return 48;
    if (alg == "HS512") return 64;
    return 0;
}

} // namespace jwt_inspector
