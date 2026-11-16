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

// alg:none should decode without throwing in both output modes — it is a
// valid (if dangerous) JWT, and the decoder's job is to flag it, not reject
// it (that's useful information for whoever is inspecting the token).
TEST(JWTDecoder, DecodeAlgNoneDoesNotThrow) {
    // header: {"alg":"none","typ":"JWT"}; payload: {"sub":"admin"}; empty signature.
    std::string token =
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
        "eyJzdWIiOiJhZG1pbiJ9.";
    EXPECT_NO_THROW(jwt_inspector::decode_token(token, false));
    EXPECT_NO_THROW(jwt_inspector::decode_token(token, true));
}

// Case variants ("None", "NONE") are a known bypass against naively
// case-sensitive "alg != none" checks, so the decoder's detection must not
// miss them either.
TEST(JWTDecoder, DecodeAlgNoneIsCaseInsensitive) {
    // header: {"alg":"NoNe"}; payload: {}; empty signature.
    std::string token = "eyJhbGciOiJOb05lIn0.e30.";
    EXPECT_NO_THROW(jwt_inspector::decode_token(token, true));
}
