# JWT Inspector

A high-performance JWT (JSON Web Token) analysis, brute-force, and forging tool with GPU-accelerated secret key discovery via OpenCL. Built for authorized security testing: cracking a weak HMAC secret, then actually forging a usable token with it — or testing whether a target blindly trusts `alg: none` or confuses an RS/ES public key for an HMAC secret.

![JWT Inspector](https://img.shields.io/badge/JWT-Inspector-blue)
![License](https://img.shields.io/badge/license-MIT-green)

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Features

- **Decode** — inspect JWT header, payload, and signature; flags `alg: none` tokens
- **CPU bruteforce** — multi-threaded dictionary attack (HS256/HS384/HS512)
- **GPU bruteforce** — OpenCL-accelerated dictionary attack (HS256)
- **Generative bruteforce** — charset + max-length pattern-based key generation
- **Signature verification** — verify RS256/RS384/RS512/ES256/ES384/ES512 with public key
- **Forge** — mint or re-sign a JWT: with a known/cracked HMAC secret, as an unsigned `alg: none` token, or via the RS256/ES256 → HS256 "algorithm confusion" attack
- **JSON output** — machine-readable output for all commands
- **Progress reporting** — real-time speed, ETA, and progress bar
- **Scriptable exit codes** — distinct codes for "found/valid", "not found", and "signature invalid" (see [Exit Codes](#exit-codes))

## Installation

Download a pre-built binary from the [Releases](https://github.com/tldr-it-stepankutaj/jwt_inspector/releases) page, or build from source.

## Building from Source

### Requirements

- C++17 compiler
- CMake 3.10+
- OpenSSL 3.x
- OpenCL (optional, for GPU acceleration)

nlohmann/json and GoogleTest are fetched automatically by CMake.

```bash
git clone https://github.com/tldr-it-stepankutaj/jwt_inspector.git
cd jwt_inspector

# Build
cmake -B build && cmake --build build --parallel

# Build without OpenCL
cmake -B build -DENABLE_OPENCL=OFF && cmake --build build --parallel

# Build with tests
cmake -B build -DBUILD_TESTS=ON && cmake --build build --parallel
cd build && ctest --output-on-failure
```

## Usage

```
jwt_inspector <command> [options]

Commands:
  decode         Decode and inspect a JWT token
  bruteforce     CPU-based dictionary attack on JWT secret
  gpu-bruteforce GPU-accelerated dictionary attack (requires OpenCL)
  generate       Generative brute-force with charset + max length
  verify         Verify JWT signature with a public key
  forge          Forge/re-sign a JWT (secret, alg:none, or RS/ES->HS "confusion")

Options:
  <token>              JWT token string (positional, or use --file)
  --file <path>        Read token from file
  --wordlist <path>    Path to wordlist file
  --threads <N>        Number of CPU threads (0 = auto-detect)
  --charset <chars>    Character set for generative bruteforce
  --max-length <N>     Maximum secret length for generative bruteforce
  --pubkey <path>      Public key PEM file (verify)
  --json               Output results as JSON
  --help               Show help
  --version            Show version

Forge options (exactly one of --secret / --confusion-pubkey / --none):
  --secret <value>          Sign with this literal HMAC secret
  --confusion-pubkey <path> Sign using an RS/ES public key's raw bytes as the
                            HMAC secret (RS256/ES256 -> HS256 "alg confusion")
  --none                    Produce an unsigned "alg":"none" token
  --alg <HS256|HS384|HS512> HMAC algorithm for --secret/--confusion-pubkey
                            (default: HS256)
  --claims <path>           JSON file whose top-level keys override the
                            payload (base token's payload, or {} if none).
                            A null value removes that claim entirely (JSON
                            Merge Patch, RFC 7396), e.g. {"exp": null}.
```

### Examples

**Decode a token:**
```bash
jwt_inspector decode eyJhbGciOiJIUzI1NiIs...
```

**Dictionary attack (CPU):**
```bash
jwt_inspector bruteforce --file token.txt --wordlist rockyou.txt --threads 8
```

**Dictionary attack (GPU):**
```bash
jwt_inspector gpu-bruteforce --file token.txt --wordlist rockyou.txt
```
> The GPU kernel uses fixed-size buffers: the token's `header.payload` must be at
> most 512 bytes and each candidate secret at most 256 bytes. Anything larger is
> rejected up front with a clear error — use `bruteforce` (CPU) for those tokens
> instead, rather than risking a silently wrong (truncated) result.

**Generative bruteforce:**
```bash
jwt_inspector generate --file token.txt --charset "abcdefghijklmnopqrstuvwxyz0123456789" --max-length 6
```

**Verify RS256 signature:**
```bash
jwt_inspector verify --file token.txt --pubkey public.pem
```

**JSON output:**
```bash
jwt_inspector decode --json eyJhbGciOiJIUzI1NiIs...
jwt_inspector bruteforce --json --file token.txt --wordlist words.txt
```

**Forge a token with a cracked/known secret:**
```bash
jwt_inspector forge --secret mysecret
# re-sign a captured token with a tweaked claim (e.g. escalate the subject):
echo '{"sub":"admin","admin":true}' > claims.json
jwt_inspector forge --secret mysecret --claims claims.json --file captured_token.txt
```

**Forge an unsigned `alg: none` token** (tests whether a target trusts the algorithm
named in the token's own header instead of pinning the algorithm it expects):
```bash
jwt_inspector forge --none --claims claims.json
```

**RS256/ES256 → HS256 "algorithm confusion" attack** — forges an HS256 token using
an RS/ES public key's raw file bytes as the HMAC secret. Hands a vulnerable verifier
(one that does e.g. `jwt.verify(token, fs.readFileSync("public.pem"))` without
pinning the expected algorithm) a token it will happily accept, because the "secret"
is a key that is, by definition, public:
```bash
jwt_inspector forge --confusion-pubkey public.pem --claims claims.json --file captured_token.txt
```

**Strip a claim entirely** (rather than override it) by setting it to `null` in the
claims file — e.g. drop expiry from a captured token instead of just pushing it
into the future:
```bash
echo '{"exp":null}' > strip_exp.json
jwt_inspector forge --secret mysecret --claims strip_exp.json --file captured_token.txt
```

## Exit Codes

Commands return distinct exit codes so results can be checked in scripts/CI without
parsing output:

| Code | Meaning |
|------|---------|
| `0`  | Success — secret found, signature valid, or decode/forge succeeded |
| `1`  | Error — bad arguments, file not found, malformed token, ... |
| `2`  | `bruteforce` / `gpu-bruteforce` / `generate` ran to completion but found nothing |
| `3`  | `verify` ran to completion but the signature is not valid |

```bash
jwt_inspector bruteforce --file token.txt --wordlist rockyou.txt --json
if [ $? -eq 0 ]; then echo "Weak secret found!"; fi
```

## Security Note

This tool — including `forge`'s `alg: none` and RS/ES→HS "confusion" attacks — is
intended for educational and authorized security testing purposes only. Use
responsibly and only on systems you own or have explicit permission to test.

## License

MIT — see [LICENSE](LICENSE) for details.
