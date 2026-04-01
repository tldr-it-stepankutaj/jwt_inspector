#include <gtest/gtest.h>
#include "jwt_decoder.hpp"

// Basic smoke test — decode should not crash on a valid HS256 token.
TEST(JWTDecoder, DecodeSmokeTest) {
    std::string token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    // Should not throw
    EXPECT_NO_THROW(jwt_inspector::decode_token(token, false));
}

TEST(JWTDecoder, DecodeJsonOutput) {
    std::string token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    // JSON mode should also not throw
    EXPECT_NO_THROW(jwt_inspector::decode_token(token, true));
}

TEST(JWTDecoder, DecodeInvalidToken) {
    EXPECT_THROW(jwt_inspector::decode_token("not.a.valid-base64!!", false), std::exception);
}
