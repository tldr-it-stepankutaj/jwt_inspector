# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-11-16

### Added
- `forge` command: mint or re-sign a JWT.
  - `--secret <value>` — sign with a literal HMAC secret (e.g. one found via `bruteforce`).
  - `--none` — produce an unsigned `alg: none` token, for testing verifiers that
    trust the algorithm named in the token's own header.
  - `--confusion-pubkey <path>` — the classic RS256/ES256 → HS256 "algorithm
    confusion" attack: signs with the raw bytes of an RS/ES public key file used as
    the HMAC secret.
  - `--claims <path>` — JSON file whose top-level keys override the payload (the
    base token's payload if one is given via a positional arg/`--file`, or `{}`),
    using JSON Merge Patch (RFC 7396) semantics: a `null` value removes that claim
    entirely instead of overriding it, e.g. `{"exp": null}` to strip expiry.
  - `--alg <HS256|HS384|HS512>` for `--secret`/`--confusion-pubkey` (default `HS256`).
- `decode` now flags `alg: none` tokens (case-insensitively, so `None`/`NONE`
  bypass variants are caught too) with a warning, in both text and `--json` output.
- Distinct process exit codes instead of always returning `0` on success: `2` when
  `bruteforce`/`gpu-bruteforce`/`generate` completes without finding the secret, `3`
  when `verify` completes with an invalid signature, so results can be checked in
  scripts/CI without parsing output. Documented in `--help` and the README.
- CLI-level smoke tests (`test_cli_smoke.cpp`) that invoke the actual built binary
  and check its exit code/output, covering argv parsing and command dispatch —
  every other test links against the library and calls functions directly,
  bypassing `cli.cpp`/`main.cpp` entirely.

### Fixed
- **GPU bruteforce silently produced wrong results for candidate secrets longer
  than 64 bytes.** The OpenCL kernel built HMAC's ipad/opad directly from the raw
  secret bytes (truncated at 64) instead of hashing keys longer than the HMAC
  block size down first, as RFC 2104 requires — so a correct secret present in the
  wordlist could never be found via GPU. Fixed in the kernel; a secret that still
  exceeds the kernel's (now 256-byte) buffer is rejected up front with a clear
  error instead of being silently truncated.
- **GPU bruteforce silently truncated tokens with a `header.payload` longer than
  512 bytes**, computing the wrong hash for every candidate and always reporting
  "not found". Now validated up front with a clear error pointing at `bruteforce`
  (CPU) instead.
- **`generate`'s search-space size could silently overflow.** A large
  `--charset`/`--max-length` combination could overflow `size_t`, producing a
  bogus small total that misled the progress/ETA display and caused most of the
  requested search space to never actually be tried. Now throws a clear error
  instead of wrapping around.

### Changed
- Deduplicated the HMAC algorithm/digest-size lookup used by `bruteforce` and
  `generate` into a single shared `hmac_md_for_alg`/`hmac_digest_size_for_alg`
  (now also reused by `forge`).
- Deduplicated whole-file reading into a single `jwt_utils::read_whole_file`
  (always binary mode), used by both `verify --pubkey` and
  `forge --confusion-pubkey`/`--claims`. `verify`'s file read previously opened
  in text mode, which on Windows could silently rewrite CRLF/LF in the key file.
- `bruteforce`/`generate` no longer spawn more worker threads than there is work
  to do.
- Progress/attempt counts now include the candidate that actually matched (it was
  previously off by one, undercounting).
- `.gitignore`: added `cmake-build-*/` (CLion's default build directory) and the
  root-level `/jwt_inspector` binary name, since a compiled binary had previously
  ended up committed by accident.

## [1.0.0] - 2026-04-16

Initial release.

### Added
- `decode` — inspect JWT header, payload, and signature.
- `bruteforce` — multi-threaded CPU dictionary attack on the HMAC secret
  (HS256/HS384/HS512).
- `gpu-bruteforce` — OpenCL-accelerated dictionary attack (HS256).
- `generate` — generative (charset + max-length) bruteforce.
- `verify` — signature verification against a public key (RS256/RS384/RS512/
  ES256/ES384/ES512).
- `--json` machine-readable output on every command.
- Real-time progress reporting (speed, ETA, progress bar).
