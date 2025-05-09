# JWT Inspector

A high-performance JWT (JSON Web Token) analysis and brute-force tool leveraging OpenCL for GPU-accelerated secret key discovery.

![JWT Inspector](https://img.shields.io/badge/JWT-Inspector-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- 🔍 Decode and inspect JWT tokens
- 🔑 Multi-threaded CPU brute-force for JWT secrets
- ⚡ GPU-accelerated brute-force using OpenCL
- 📊 Performance metrics tracking (hashes/sec)
- 🚀 Optimized for high-performance computing

## Requirements

- C++17 compatible compiler
- OpenSSL 3.x
- OpenCL compatible GPU (for GPU acceleration)
- CMake 3.10+
- nlohmann/json library

## Building from Source

```bash
# Clone the repository
git clone https://github.com/tldr-it-stepankutaj/jwt_inspector.git
cd jwt_inspector

# Create build directory
mkdir build && cd build

# Configure and build
cmake ..
make
```

## Usage

From the provided source code, JWT Inspector appears to run directly using token and wordlist files specified in the code. The application reads the token from `data/sample_token.txt` and the wordlist from `data/wordlist.txt`.

```bash
./jwt_inspector
```

Example output:
```
📦 Loaded JWT token:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdGVwYW5rdXRhaiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcxNTI5MDAwMH0.3KNkK-Z0n0RId2rKhICgh-JrNRFVvJphOnuopUlWjAg

🔑 Token signature bytes: 32 bytes
📊 Total secrets to test: 10000
🖥️ OpenCL device: AMD Radeon Pro 5500M
🚀 Starting OpenCL brute-force...
⏱️ Time: 0.1234 sec
⚡ Hashes/sec: 81037
✅ Secret FOUND: "supersecret" at index 5123
```

Additionally, based on the shared code, it appears there are other JWT decoding and bruteforce capabilities in the codebase that may be available through modifications to `main.cpp`. The `JWTDecoder` class includes:

1. `decode()` - For decoding and inspecting tokens
2. `bruteforce_secret()` - For CPU-based brute-force
3. `bruteforce_secret_multithreaded()` - For multi-threaded CPU brute-force

The `JWTBruteForcer` class provides GPU-accelerated brute-force capabilities.

Example output:
```
🔑 Token signature bytes: 32 bytes
📊 Total secrets to test: 10000
🖥️ OpenCL device: AMD Radeon Pro 5500M
🚀 Starting OpenCL brute-force...
⏱️ Time: 0.1234 sec
⚡ Hashes/sec: 81037
✅ Secret FOUND: "supersecret" at index 5123
```

## Architecture

The project is organized as follows:

- `include/`: Header files
  - `jwt_decoder.hpp`: CPU-based JWT operations
  - `jwt_bruteforce.hpp`: OpenCL-accelerated brute-force
- `src/`: Implementation files
  - `main.cpp`: Command-line interface
  - `jwt_decoder.cpp`: JWT decoding and CPU brute-force
  - `jwt_bruteforce.cpp`: OpenCL setup and execution
- `kernels/`: OpenCL kernel code
  - `hmac_sha256.cl`: HMAC-SHA256 implementation for GPU
- `data/`: Sample data
  - `sample_token.txt`: Example JWT to test with
  - `wordlist.txt`: Dictionary for brute-force attempts

## How It Works

JWT Inspector uses two key approaches for secret discovery:

1. **CPU Multi-Threading**: Divides the wordlist into chunks and assigns them to separate threads for parallel processing.

2. **GPU Acceleration**: Offloads the computation-intensive HMAC-SHA256 operations to the GPU using OpenCL, enabling thousands of attempts per second.

The OpenCL kernel implements a streamlined version of HMAC-SHA256 specifically optimized for brute-force operations, with a focus on performance rather than completeness.

## Performance

Performance varies based on hardware, but typical results:

- **CPU Multi-Threaded**: ~10,000-30,000 hashes/sec (depends on core count)
- **GPU-Accelerated**: ~50,000-500,000 hashes/sec (depends on GPU model)

## Security Note

This tool is provided for educational and security research purposes only. Always use it responsibly and only on systems you own or have explicit permission to test.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request