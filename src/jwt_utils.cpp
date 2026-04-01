#include "jwt_utils.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

namespace jwt_utils {

// ---------------------------------------------------------------------------
// base64url helpers
// ---------------------------------------------------------------------------

namespace {

/// Custom deleter for OpenSSL BIO chains — frees the entire chain.
struct BIOChainDeleter {
    void operator()(BIO* bio) const noexcept {
        if (bio) BIO_free_all(bio);
    }
};

using BIOPtr = std::unique_ptr<BIO, BIOChainDeleter>;

/// Convert base64url to standard base64 by replacing characters and adding
/// padding so that OpenSSL's decoder is happy.
std::string base64url_to_base64(const std::string& input) {
    std::string out = input;
    std::replace(out.begin(), out.end(), '-', '+');
    std::replace(out.begin(), out.end(), '_', '/');
    // Pad to a multiple of 4.
    while (out.size() % 4 != 0) {
        out.push_back('=');
    }
    return out;
}

/// Convert standard base64 to base64url by replacing characters and stripping
/// any trailing '=' padding.
std::string base64_to_base64url(const std::string& input) {
    std::string out = input;
    std::replace(out.begin(), out.end(), '+', '-');
    std::replace(out.begin(), out.end(), '/', '_');
    // Remove padding.
    out.erase(std::remove(out.begin(), out.end(), '='), out.end());
    return out;
}

} // anonymous namespace

std::vector<uint8_t> base64url_decode(const std::string& input) {
    std::string b64 = base64url_to_base64(input);

    BIOPtr b64_bio(BIO_new(BIO_f_base64()));
    if (!b64_bio) {
        throw std::runtime_error("base64url_decode: failed to create base64 BIO");
    }
    BIO_set_flags(b64_bio.get(), BIO_FLAGS_BASE64_NO_NL);

    BIO* mem_bio = BIO_new_mem_buf(b64.data(), static_cast<int>(b64.size()));
    if (!mem_bio) {
        throw std::runtime_error("base64url_decode: failed to create mem BIO");
    }
    // Push chains ownership: b64_bio now owns mem_bio.
    BIO_push(b64_bio.get(), mem_bio);

    // Decoded output can be at most as large as the encoded input.
    std::vector<uint8_t> decoded(b64.size());
    int len = BIO_read(b64_bio.get(), decoded.data(), static_cast<int>(decoded.size()));
    if (len < 0) {
        throw std::runtime_error("base64url_decode: BIO_read failed");
    }
    decoded.resize(static_cast<size_t>(len));
    return decoded;
}

std::string base64url_encode(const uint8_t* data, size_t len) {
    BIOPtr b64_bio(BIO_new(BIO_f_base64()));
    if (!b64_bio) {
        throw std::runtime_error("base64url_encode: failed to create base64 BIO");
    }
    BIO_set_flags(b64_bio.get(), BIO_FLAGS_BASE64_NO_NL);

    BIO* mem_bio = BIO_new(BIO_s_mem());
    if (!mem_bio) {
        throw std::runtime_error("base64url_encode: failed to create mem BIO");
    }
    // Push chains ownership: b64_bio now owns mem_bio.
    BIO_push(b64_bio.get(), mem_bio);

    if (BIO_write(b64_bio.get(), data, static_cast<int>(len)) < 0) {
        throw std::runtime_error("base64url_encode: BIO_write failed");
    }
    BIO_flush(b64_bio.get());

    BUF_MEM* buf_mem = nullptr;
    BIO_get_mem_ptr(mem_bio, &buf_mem);

    std::string b64(buf_mem->data, buf_mem->length);
    return base64_to_base64url(b64);
}

// ---------------------------------------------------------------------------
// Token splitting / parsing
// ---------------------------------------------------------------------------

TokenParts split_token(const std::string& token) {
    TokenParts parts;

    auto first_dot = token.find('.');
    if (first_dot == std::string::npos) {
        throw std::runtime_error("Invalid JWT: missing first '.' delimiter");
    }

    auto second_dot = token.find('.', first_dot + 1);
    if (second_dot == std::string::npos) {
        throw std::runtime_error("Invalid JWT: missing second '.' delimiter");
    }

    // Make sure there is no third dot.
    if (token.find('.', second_dot + 1) != std::string::npos) {
        throw std::runtime_error("Invalid JWT: token contains more than 3 parts");
    }

    parts.header_b64  = token.substr(0, first_dot);
    parts.payload_b64 = token.substr(first_dot + 1, second_dot - first_dot - 1);
    parts.signature_b64 = token.substr(second_dot + 1);
    parts.header_payload = token.substr(0, second_dot);

    return parts;
}

nlohmann::json decode_json_part(const std::string& b64_part) {
    auto bytes = base64url_decode(b64_part);
    std::string json_str(bytes.begin(), bytes.end());
    return nlohmann::json::parse(json_str);
}

std::string parse_header_alg(const std::string& header_b64) {
    auto header = decode_json_part(header_b64);
    if (!header.contains("alg")) {
        throw std::runtime_error("JWT header does not contain an 'alg' field");
    }
    return header["alg"].get<std::string>();
}

std::string format_timestamp(long timestamp) {
    std::time_t t = static_cast<std::time_t>(timestamp);
    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &t);
#else
    gmtime_r(&t, &utc);
#endif
    std::ostringstream oss;
    oss << std::put_time(&utc, "%Y-%m-%d %H:%M:%S") << " UTC";
    return oss.str();
}

} // namespace jwt_utils
