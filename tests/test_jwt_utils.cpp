#include <gtest/gtest.h>
#include "jwt_utils.hpp"

using namespace jwt_utils;

TEST(Base64Url, RoundTrip) {
    const std::string original = "Hello, World!";
    std::vector<uint8_t> data(original.begin(), original.end());
    std::string encoded = base64url_encode(data.data(), data.size());
    auto decoded = base64url_decode(encoded);
    std::string result(decoded.begin(), decoded.end());
    EXPECT_EQ(result, original);
}

TEST(Base64Url, EmptyInput) {
    auto decoded = base64url_decode("");
    EXPECT_TRUE(decoded.empty());
}

TEST(Base64Url, KnownVector) {
    // "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" decodes to {"alg":"HS256","typ":"JWT"}
    auto decoded = base64url_decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
    std::string json(decoded.begin(), decoded.end());
    EXPECT_EQ(json, R"({"alg":"HS256","typ":"JWT"})");
}

TEST(Base64Url, UrlUnsafeChars) {
    // Test round-trip of binary data that produces +, /, = in standard base64
    uint8_t data[] = {0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa};
    std::string encoded = base64url_encode(data, sizeof(data));
    EXPECT_EQ(encoded.find('+'), std::string::npos);
    EXPECT_EQ(encoded.find('/'), std::string::npos);
    EXPECT_EQ(encoded.find('='), std::string::npos);

    auto decoded = base64url_decode(encoded);
    ASSERT_EQ(decoded.size(), sizeof(data));
    EXPECT_EQ(std::memcmp(decoded.data(), data, sizeof(data)), 0);
}

TEST(SplitToken, ValidThreeParts) {
    auto parts = split_token("aaa.bbb.ccc");
    EXPECT_EQ(parts.header_b64, "aaa");
    EXPECT_EQ(parts.payload_b64, "bbb");
    EXPECT_EQ(parts.signature_b64, "ccc");
    EXPECT_EQ(parts.header_payload, "aaa.bbb");
}

TEST(SplitToken, TwoParts) {
    EXPECT_THROW(split_token("aaa.bbb"), std::runtime_error);
}

TEST(SplitToken, FourParts) {
    EXPECT_THROW(split_token("a.b.c.d"), std::runtime_error);
}

TEST(SplitToken, Empty) {
    EXPECT_THROW(split_token(""), std::runtime_error);
}

TEST(ParseHeaderAlg, HS256) {
    // Base64url of {"alg":"HS256","typ":"JWT"}
    std::string alg = parse_header_alg("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
    EXPECT_EQ(alg, "HS256");
}

TEST(DecodeJsonPart, ValidJson) {
    auto json = decode_json_part("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
    EXPECT_EQ(json["alg"], "HS256");
    EXPECT_EQ(json["typ"], "JWT");
}

TEST(FormatTimestamp, KnownDate) {
    // 2024-05-10 00:00:00 UTC = 1715299200
    std::string formatted = format_timestamp(1715299200);
    EXPECT_EQ(formatted, "2024-05-10 00:00:00 UTC");
}
