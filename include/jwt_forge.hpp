#pragma once

#include <optional>
#include <string>

namespace jwt_inspector {

enum class ForgeSigningMode {
    Secret,
    /// --confusion-pubkey <path>: HMAC-sign using the *raw bytes* of this PEM
    /// file as the HMAC secret. This is the classic RS256/ES256 -> HS256
    /// "algorithm confusion" attack: a verifier that does something like
    /// `jwt.verify(token, fs.readFileSync("public.pem"))` without pinning the
    /// expected algorithm will happily accept a token "signed" this way,
    /// because the public key — which is, by definition, public — is being
    /// reused as a symmetric HMAC secret.
    ConfusionPubkey,
    /// --none: produce an unsigned token with header `{"alg":"none"}` and an
    /// empty signature segment. Tests whether the target blindly trusts the
    /// algorithm named in the (attacker-controlled) token header.
    None
};

struct ForgeOptions {
    /// Optional base token (e.g. one captured from a real request) to take the
    /// header and payload from. Empty means "start from a bare header and an
    /// empty payload object".
    std::string base_token;

    ForgeSigningMode mode = ForgeSigningMode::Secret;
    std::string secret;                 // used when mode == Secret
    std::string confusion_pubkey_path;  // used when mode == ConfusionPubkey

    /// HMAC algorithm to sign with (HS256/HS384/HS512). Ignored when
    /// mode == None, where the header's "alg" is always forced to "none".
    std::string hmac_alg = "HS256";

    /// Optional path to a JSON file whose top-level keys are merged into the
    /// base payload (JSON Merge Patch, RFC 7396 semantics): a non-null value
    /// adds/overrides that claim (e.g. {"sub": "admin"} to escalate a
    /// captured token's subject before re-signing it), a `null` value removes
    /// the claim entirely (e.g. {"exp": null} to strip expiry instead of just
    /// pushing it into the future).
    std::optional<std::string> claims_file;
};

struct ForgeResult {
    std::string token;
    std::string algorithm;        // the "alg" header value actually used
    bool confusion_attack = false; // true if mode == ConfusionPubkey
};

/// Forges a new JWT per `opts`. Throws std::runtime_error if the base token,
/// the claims file, or the confusion-pubkey file cannot be read/parsed, or if
/// hmac_alg is not one of HS256/HS384/HS512 for a signing mode that needs it.
ForgeResult forge_token(const ForgeOptions& opts);

} // namespace jwt_inspector
