#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace jwt_utils {

struct TokenParts {
    std::string header_b64;
    std::string payload_b64;
    std::string signature_b64;
    std::string header_payload; // "header.payload" for HMAC
};

/// Decode a base64url-encoded string to raw bytes.
/// Uses OpenSSL BIO with RAII — no malloc/free.
std::vector<uint8_t> base64url_decode(const std::string& input);

/// Encode raw bytes to a base64url string (no padding).
std::string base64url_encode(const uint8_t* data, size_t len);

/// Split a JWT token into its three dot-separated parts.
/// Throws std::runtime_error if the token does not have exactly 3 parts.
TokenParts split_token(const std::string& token);

/// Decode the JWT header and return the value of the "alg" field.
std::string parse_header_alg(const std::string& header_b64);

/// Decode a base64url-encoded part and parse it as JSON.
nlohmann::json decode_json_part(const std::string& b64_part);

/// Format a Unix timestamp as "YYYY-MM-DD HH:MM:SS UTC".
std::string format_timestamp(long timestamp);

} // namespace jwt_utils
