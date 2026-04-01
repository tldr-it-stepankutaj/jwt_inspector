# JWT Inspector

A high-performance JWT (JSON Web Token) analysis and brute-force tool with GPU-accelerated secret key discovery via OpenCL.

![JWT Inspector](https://img.shields.io/badge/JWT-Inspector-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Decode** — inspect JWT header, payload, and signature
- **CPU bruteforce** — multi-threaded dictionary attack (HS256/HS384/HS512)
- **GPU bruteforce** — OpenCL-accelerated dictionary attack (HS256)
- **Generative bruteforce** — charset + max-length pattern-based key generation
- **Signature verification** — verify RS256/RS384/RS512/ES256/ES384/ES512 with public key
- **JSON output** — machine-readable output for all commands
- **Progress reporting** — real-time speed, ETA, and progress bar

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

## Security Note

This tool is intended for educational and authorized security testing purposes only. Use responsibly and only on systems you own or have explicit permission to test.

## License

MIT — see [LICENSE](LICENSE) for details.
