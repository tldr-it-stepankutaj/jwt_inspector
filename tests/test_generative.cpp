#include <gtest/gtest.h>
#include "jwt_bruteforce.hpp"

// HS256 JWT signed with secret "secret"
static const char* TEST_TOKEN =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjAwMDAwMDAwfQ."
    "7RQs5OrajGpqLnkn4YKPV6ZoxlAlg80L20LREEUCDyY";

TEST(GenerativeBruteforce, FindsShortSecret) {
    // "secret" is 6 chars from [a-z]. Use charset "ceorst" to keep search space small.
    // With max_length=6 and charset "ceorst" (6 chars), total = 6+36+216+1296+7776+46656 = 55986
    auto result = jwt_inspector::generative_bruteforce(TEST_TOKEN, "ceorst", 6, 2, true);
    EXPECT_TRUE(result.found);
    EXPECT_EQ(result.secret, "secret");
}

TEST(GenerativeBruteforce, SecretNotInCharset) {
    // "secret" cannot be found if charset doesn't contain all its characters
    auto result = jwt_inspector::generative_bruteforce(TEST_TOKEN, "ab", 6, 1, true);
    EXPECT_FALSE(result.found);
}

TEST(GenerativeBruteforce, EmptyCharsetThrows) {
    EXPECT_THROW(
        jwt_inspector::generative_bruteforce(TEST_TOKEN, "", 4, 1, true),
        std::runtime_error
    );
}

TEST(GenerativeBruteforce, ZeroMaxLengthThrows) {
    EXPECT_THROW(
        jwt_inspector::generative_bruteforce(TEST_TOKEN, "abc", 0, 1, true),
        std::runtime_error
    );
}
