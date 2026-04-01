#pragma once

#include <string>

namespace jwt_inspector {

struct VerifyResult {
    bool valid = false;
    std::string algorithm;
    std::string error;
};

/// Verify JWT signature using a public key (PEM).
/// Supports RS256, RS384, RS512, ES256, ES384, ES512.
/// Auto-detects algorithm from the JWT header.
VerifyResult verify_token(const std::string& token, const std::string& pubkey_pem,
                          bool json_output = false);

} // namespace jwt_inspector
