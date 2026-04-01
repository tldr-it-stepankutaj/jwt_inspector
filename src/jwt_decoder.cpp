#include "jwt_decoder.hpp"
#include "jwt_utils.hpp"

#include <iostream>
#include <sstream>

namespace jwt_inspector {

namespace {

void print_json_value(const nlohmann::json& val, const std::string& key) {
    if (val.is_number_integer()) {
        // Check for timestamp fields
        if (key == "iat" || key == "exp" || key == "nbf" || key == "auth_time") {
            long ts = val.get<long>();
            std::cout << "  " << key << ": " << ts
                      << " (" << jwt_utils::format_timestamp(ts) << ")\n";
            return;
        }
    }
    std::cout << "  " << key << ": " << val.dump() << "\n";
}

} // anonymous namespace

void decode_token(const std::string& token, bool json_output) {
    auto parts = jwt_utils::split_token(token);
    auto header = jwt_utils::decode_json_part(parts.header_b64);
    auto payload = jwt_utils::decode_json_part(parts.payload_b64);

    if (json_output) {
        nlohmann::json out;
        out["header"] = header;
        out["payload"] = payload;
        out["signature"] = parts.signature_b64;
        std::cout << out.dump(2) << "\n";
        return;
    }

    std::cout << "Header:\n";
    for (auto& [key, val] : header.items()) {
        std::cout << "  " << key << ": " << val.dump() << "\n";
    }

    std::cout << "\nPayload:\n";
    for (auto& [key, val] : payload.items()) {
        print_json_value(val, key);
    }

    std::cout << "\nSignature (base64url):\n  " << parts.signature_b64 << "\n";
}

} // namespace jwt_inspector
