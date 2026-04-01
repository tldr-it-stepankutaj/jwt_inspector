#pragma once
#include <string>
#include <optional>

enum class Command {
    Decode,
    CpuBruteforce,
    GpuBruteforce,
    Generate,
    Verify,
    Help,
    Version
};

struct CLIOptions {
    Command command = Command::Help;

    // Token - either direct string or file path
    std::string token;                      // raw token string (set after resolving --file)
    std::optional<std::string> token_file;  // --file path

    // Bruteforce options
    std::optional<std::string> wordlist;    // --wordlist path
    unsigned int threads = 0;               // --threads N (0 = auto-detect)

    // Generative bruteforce options
    std::string charset;                    // --charset "abc..."
    size_t max_length = 0;                  // --max-length N

    // Verify options
    std::optional<std::string> pubkey;      // --pubkey path

    // Output options
    bool json_output = false;               // --json
};

CLIOptions parse_args(int argc, char* argv[]);
void print_usage();
void print_version();
