# Contributing to jwt_inspector

Thank you for your interest in contributing. This document outlines the process
for contributing to this project.

## Prerequisites

- CMake >= 3.10
- C++17-compatible compiler
- OpenSSL 3.x development headers
- OpenCL-compatible GPU (optional; can be disabled with `-DENABLE_OPENCL=OFF`)

## Getting Started

1. Fork the repository.
2. Clone your fork locally.
3. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. Build the project:
   ```bash
   cmake -B build && cmake --build build
   ```
5. Make your changes and verify the build still succeeds.

## Submitting Changes

1. Commit your changes with clear, descriptive commit messages.
2. Push your branch to your fork.
3. Open a Pull Request against the `main` branch of this repository.
4. Describe your changes and the motivation behind them in the PR description.

## Guidelines

- Follow the existing code style and conventions in the project.
- Keep changes focused. One PR should address one concern.
- Ensure the project builds cleanly before submitting.
- Update documentation if your change affects public interfaces or usage.

## OpenSSL Note

The default `CMakeLists.txt` references the Homebrew OpenSSL path
(`/opt/homebrew/opt/openssl@3`). If you are building on a different platform,
you may need to adjust the OpenSSL path or set `OPENSSL_ROOT_DIR` accordingly.

## Questions

If you have questions about contributing, open an issue on the repository.
