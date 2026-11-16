#include <gtest/gtest.h>
#include "jwt_bruteforce.hpp"
#include "jwt_utils.hpp"

// These tests exercise the real GPU path end to end (they require an actual
// OpenCL device, the same as running `jwt_inspector gpu-bruteforce`). When the
// project is built with -DENABLE_OPENCL=OFF (HAS_OPENCL undefined), the test
// bodies are skipped so the test binary still builds and runs cleanly, but the
// regression coverage they provide only applies to OpenCL builds.
#ifdef HAS_OPENCL

namespace {

// HS256 JWT signed with the literal secret "secret".
const char* kShortSecretToken =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjAwMDAwMDAwfQ."
    "7RQs5OrajGpqLnkn4YKPV6ZoxlAlg80L20LREEUCDyY";

// HS256 JWT signed with a 74-byte secret (longer than the HMAC block size of
// 64 bytes, which per RFC 2104 must be hashed down before use as the HMAC key).
const char* kLongSecret =
    "this_is_a_secret_that_is_definitely_longer_than_sixty_four_bytes_long_1234";
const char* kLongSecretToken =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjAwMDAwMDAwfQ."
    "Grc1kvbT60zhj9RMfdiHZICrUbAc5yklYegn1OW47kg";

} // namespace

TEST(GpuBruteforce, FindsKnownSecret) {
    std::vector<std::string> wordlist = {"password", "123456", "secret", "admin"};
    auto result = jwt_inspector::gpu_bruteforce(kShortSecretToken, wordlist, true);
    EXPECT_TRUE(result.found);
    EXPECT_EQ(result.secret, "secret");
}

TEST(GpuBruteforce, SecretNotInWordlist) {
    std::vector<std::string> wordlist = {"password", "123456", "admin"};
    auto result = jwt_inspector::gpu_bruteforce(kShortSecretToken, wordlist, true);
    EXPECT_FALSE(result.found);
}

// Regression test for a bug where the kernel built ipad/opad directly from the
// raw secret bytes (truncated at 64) instead of hashing keys longer than the
// HMAC block size down first, as RFC 2104 requires. A >64-byte secret present
// in the wordlist used to be silently unfindable via GPU.
TEST(GpuBruteforce, FindsSecretLongerThanHmacBlockSize) {
    ASSERT_GT(std::string(kLongSecret).size(), 64u);
    std::vector<std::string> wordlist = {"password", "123456", kLongSecret, "admin"};
    auto result = jwt_inspector::gpu_bruteforce(kLongSecretToken, wordlist, true);
    EXPECT_TRUE(result.found);
    EXPECT_EQ(result.secret, kLongSecret);
}

// Regression test: a candidate secret that exceeds the kernel's fixed buffer
// (MAX_SECRET_LEN) must be rejected with a clear error, not silently truncated.
TEST(GpuBruteforce, OversizedSecretInWordlistThrows) {
    std::string huge_secret(300, 'x');
    std::vector<std::string> wordlist = {"password", huge_secret};
    EXPECT_THROW(jwt_inspector::gpu_bruteforce(kShortSecretToken, wordlist, true),
                 std::runtime_error);
}

// Regression test: a token whose header.payload exceeds the kernel's fixed
// message buffer (MAX_MSG_LEN) must be rejected with a clear error up front,
// not silently truncated (which would compute the wrong hash for every
// candidate and always report "not found").
TEST(GpuBruteforce, OversizedHeaderPayloadThrows) {
    // header: {"alg":"HS256","typ":"JWT"}; payload padded well past 512 bytes.
    // The signature segment just needs to decode to 32 bytes (any 32 bytes —
    // it is never actually checked, because the oversized-header error fires
    // first) so that the test exercises the header-length check specifically,
    // not the unrelated "wrong signature size" check.
    std::vector<uint8_t> dummy_sig(32, 0);
    std::string sig_b64 = jwt_utils::base64url_encode(dummy_sig.data(), dummy_sig.size());

    std::string header_b64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    std::string payload_b64(600, 'A'); // not valid JSON once decoded, but the
                                        // length check happens before parsing.
    std::string token = header_b64 + "." + payload_b64 + "." + sig_b64;
    std::vector<std::string> wordlist = {"password"};
    EXPECT_THROW(jwt_inspector::gpu_bruteforce(token, wordlist, true),
                 std::runtime_error);
}

#endif // HAS_OPENCL
