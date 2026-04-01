#include <gtest/gtest.h>
#include "jwt_bruteforce.hpp"

// HS256 JWT signed with secret "secret":
// Header: {"alg":"HS256","typ":"JWT"}
// Payload: {"sub":"test","iat":1600000000}
static const char* TEST_TOKEN =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjAwMDAwMDAwfQ."
    "7RQs5OrajGpqLnkn4YKPV6ZoxlAlg80L20LREEUCDyY";

TEST(CpuBruteforce, FindsKnownSecret) {
    std::vector<std::string> wordlist = {"password", "123456", "secret", "admin"};
    auto result = jwt_inspector::cpu_bruteforce(TEST_TOKEN, wordlist, 2, true);
    EXPECT_TRUE(result.found);
    EXPECT_EQ(result.secret, "secret");
}

TEST(CpuBruteforce, SecretNotInWordlist) {
    std::vector<std::string> wordlist = {"password", "123456", "admin"};
    auto result = jwt_inspector::cpu_bruteforce(TEST_TOKEN, wordlist, 2, true);
    EXPECT_FALSE(result.found);
}

TEST(CpuBruteforce, EmptyWordlist) {
    std::vector<std::string> wordlist;
    auto result = jwt_inspector::cpu_bruteforce(TEST_TOKEN, wordlist, 1, true);
    EXPECT_FALSE(result.found);
    EXPECT_EQ(result.attempts, 0u);
}

TEST(CpuBruteforce, SingleThread) {
    std::vector<std::string> wordlist = {"wrong1", "wrong2", "secret"};
    auto result = jwt_inspector::cpu_bruteforce(TEST_TOKEN, wordlist, 1, true);
    EXPECT_TRUE(result.found);
    EXPECT_EQ(result.secret, "secret");
}
