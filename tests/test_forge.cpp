#include <gtest/gtest.h>
#include "jwt_forge.hpp"
#include "jwt_utils.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>

#include <openssl/hmac.h>

namespace {

/// Writes `content` to a uniquely-named temp file and returns its path. The
/// file is removed when the returned guard goes out of scope. Portable
/// across platforms (no PID/mkstemp APIs): uniqueness comes from a
/// process-lifetime counter plus the construction time.
class TempFile {
public:
    explicit TempFile(const std::string& content) {
        static std::atomic<int> counter{0};
        auto dir = std::filesystem::temp_directory_path();
        auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        path_ = (dir / ("jwt_inspector_test_" + std::to_string(now) + "_" +
                        std::to_string(counter.fetch_add(1)) + ".tmp"))
                    .string();
        std::ofstream(path_) << content;
    }
    ~TempFile() { std::remove(path_.c_str()); }
    const std::string& path() const { return path_; }

private:
    std::string path_;
};

std::string sign_hmac_sha256(const std::string& key, const std::string& signing_input) {
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(signing_input.data()), signing_input.size(),
         buf, &len);
    return jwt_utils::base64url_encode(buf, len);
}

} // namespace

using jwt_inspector::ForgeOptions;
using jwt_inspector::ForgeSigningMode;
using jwt_inspector::forge_token;

TEST(Forge, SecretFromScratchProducesVerifiableToken) {
    ForgeOptions opts;
    opts.mode = ForgeSigningMode::Secret;
    opts.secret = "mysecret";

    auto result = forge_token(opts);
    EXPECT_EQ(result.algorithm, "HS256");
    EXPECT_FALSE(result.confusion_attack);

    auto parts = jwt_utils::split_token(result.token);
    auto header = jwt_utils::decode_json_part(parts.header_b64);
    auto payload = jwt_utils::decode_json_part(parts.payload_b64);
    EXPECT_EQ(header["alg"], "HS256");
    EXPECT_TRUE(payload.empty());

    std::string expected_sig = sign_hmac_sha256("mysecret", parts.header_payload);
    EXPECT_EQ(parts.signature_b64, expected_sig);
}

TEST(Forge, HonorsRequestedHmacAlgorithm) {
    ForgeOptions opts;
    opts.mode = ForgeSigningMode::Secret;
    opts.secret = "mysecret";
    opts.hmac_alg = "HS384";

    auto result = forge_token(opts);
    EXPECT_EQ(result.algorithm, "HS384");

    auto parts = jwt_utils::split_token(result.token);
    auto header = jwt_utils::decode_json_part(parts.header_b64);
    EXPECT_EQ(header["alg"], "HS384");
}

TEST(Forge, UnknownHmacAlgorithmThrows) {
    ForgeOptions opts;
    opts.mode = ForgeSigningMode::Secret;
    opts.secret = "mysecret";
    opts.hmac_alg = "HS1";
    EXPECT_THROW(forge_token(opts), std::runtime_error);
}

TEST(Forge, ClaimsFileOverridesBaseTokenPayload) {
    // HS256 token: {"alg":"HS256","typ":"JWT"} / {"sub":"test","iat":1600000000}
    std::string base_token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjAwMDAwMDAwfQ."
        "7RQs5OrajGpqLnkn4YKPV6ZoxlAlg80L20LREEUCDyY";

    TempFile claims(R"({"sub":"admin","admin":true})");

    ForgeOptions opts;
    opts.mode = ForgeSigningMode::Secret;
    opts.secret = "secret"; // the base token's real secret, for a believable re-sign
    opts.base_token = base_token;
    opts.claims_file = claims.path();

    auto result = forge_token(opts);
    auto parts = jwt_utils::split_token(result.token);
    auto payload = jwt_utils::decode_json_part(parts.payload_b64);

    EXPECT_EQ(payload["sub"], "admin");       // overridden
    EXPECT_EQ(payload["admin"], true);        // added
    EXPECT_EQ(payload["iat"], 1600000000);    // untouched claim is preserved
}

TEST(Forge, ClaimsFileNullValueRemovesClaim) {
    // HS256 token: {"alg":"HS256","typ":"JWT"} / {"sub":"test","iat":1600000000}
    std::string base_token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjAwMDAwMDAwfQ."
        "7RQs5OrajGpqLnkn4YKPV6ZoxlAlg80L20LREEUCDyY";

    // JSON Merge Patch (RFC 7396) semantics: null removes the key entirely,
    // e.g. to strip an expiry claim rather than just overriding it.
    TempFile claims(R"({"iat":null,"sub":"admin"})");

    ForgeOptions opts;
    opts.mode = ForgeSigningMode::Secret;
    opts.secret = "secret";
    opts.base_token = base_token;
    opts.claims_file = claims.path();

    auto result = forge_token(opts);
    auto parts = jwt_utils::split_token(result.token);
    auto payload = jwt_utils::decode_json_part(parts.payload_b64);

    EXPECT_EQ(payload["sub"], "admin");
    EXPECT_FALSE(payload.contains("iat"));
}

TEST(Forge, ClaimsFileMustBeJsonObject) {
    TempFile claims("[1,2,3]");
    ForgeOptions opts;
    opts.mode = ForgeSigningMode::Secret;
    opts.secret = "x";
    opts.claims_file = claims.path();
    EXPECT_THROW(forge_token(opts), std::runtime_error);
}

TEST(Forge, NoneModeProducesEmptySignatureSegment) {
    ForgeOptions opts;
    opts.mode = ForgeSigningMode::None;

    auto result = forge_token(opts);
    EXPECT_EQ(result.algorithm, "none");
    EXPECT_FALSE(result.confusion_attack);

    // 3 parts, last one empty — not 2 parts without a trailing dot.
    ASSERT_EQ(std::count(result.token.begin(), result.token.end(), '.'), 2);
    auto parts = jwt_utils::split_token(result.token);
    EXPECT_EQ(parts.signature_b64, "");

    auto header = jwt_utils::decode_json_part(parts.header_b64);
    EXPECT_EQ(header["alg"], "none");
}

TEST(Forge, ConfusionPubkeySignsWithRawFileBytes) {
    std::string pem_like = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZI...fake...\n-----END PUBLIC KEY-----\n";
    TempFile pubkey(pem_like);

    ForgeOptions opts;
    opts.mode = ForgeSigningMode::ConfusionPubkey;
    opts.confusion_pubkey_path = pubkey.path();

    auto result = forge_token(opts);
    EXPECT_EQ(result.algorithm, "HS256");
    EXPECT_TRUE(result.confusion_attack);

    auto parts = jwt_utils::split_token(result.token);
    auto header = jwt_utils::decode_json_part(parts.header_b64);
    EXPECT_EQ(header["alg"], "HS256");

    // The signature must be exactly HMAC-SHA256 keyed with the raw file bytes
    // (not, say, a hash of the key, or the key with whitespace stripped) —
    // this is the whole point of the attack: reproduce byte-for-byte what a
    // vulnerable `jwt.verify(token, fs.readFileSync(pubkeyPath))` call does.
    std::string expected_sig = sign_hmac_sha256(pem_like, parts.header_payload);
    EXPECT_EQ(parts.signature_b64, expected_sig);
}

TEST(Forge, ConfusionPubkeyMissingFileThrows) {
    ForgeOptions opts;
    opts.mode = ForgeSigningMode::ConfusionPubkey;
    opts.confusion_pubkey_path = "/nonexistent/path/does-not-exist.pem";
    EXPECT_THROW(forge_token(opts), std::runtime_error);
}

TEST(Forge, InvalidBaseTokenThrows) {
    ForgeOptions opts;
    opts.mode = ForgeSigningMode::Secret;
    opts.secret = "x";
    opts.base_token = "not-a-valid-jwt";
    EXPECT_THROW(forge_token(opts), std::runtime_error);
}
