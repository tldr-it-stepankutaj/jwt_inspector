#include "cli.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>

static constexpr const char* VERSION = "0.1.0";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string trim(const std::string& s) {
    auto start = s.begin();
    while (start != s.end() && std::isspace(static_cast<unsigned char>(*start)))
        ++start;

    auto end = s.end();
    while (end != start && std::isspace(static_cast<unsigned char>(*(end - 1))))
        --end;

    return {start, end};
}

static std::string read_first_line(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open())
        throw std::runtime_error("Cannot open token file: " + path);

    std::string line;
    if (!std::getline(file, line))
        throw std::runtime_error("Token file is empty: " + path);

    return trim(line);
}

static Command parse_command(const std::string& arg) {
    if (arg == "decode")         return Command::Decode;
    if (arg == "bruteforce")     return Command::CpuBruteforce;
    if (arg == "gpu-bruteforce") return Command::GpuBruteforce;
    if (arg == "generate")       return Command::Generate;
    if (arg == "verify")         return Command::Verify;
    if (arg == "help" || arg == "--help" || arg == "-h")
        return Command::Help;
    if (arg == "version" || arg == "--version" || arg == "-v")
        return Command::Version;

    throw std::runtime_error("Unknown command: " + arg);
}

static void require_next_arg(int i, int argc, const std::string& flag) {
    if (i + 1 >= argc)
        throw std::runtime_error("Option " + flag + " requires an argument");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void print_usage() {
    std::cout <<
R"(Usage: jwt_inspector <command> [options]

Commands:
  decode        Decode and inspect a JWT token
  bruteforce    CPU-based dictionary attack on JWT secret
  gpu-bruteforce GPU-accelerated dictionary attack (requires OpenCL)
  generate      Generative brute-force with charset + max length
  verify        Verify JWT signature with a public key (RS256/ES256)

Options:
  <token>              JWT token string (positional, or use --file)
  --file <path>        Read token from file
  --wordlist <path>    Path to wordlist file (bruteforce/gpu-bruteforce)
  --threads <N>        Number of CPU threads (0 = auto-detect, default)
  --charset <chars>    Character set for generative bruteforce
  --max-length <N>     Maximum secret length for generative bruteforce
  --pubkey <path>      Public key PEM file (verify)
  --json               Output results as JSON
  --help               Show this help
  --version            Show version
)";
}

void print_version() {
    std::cout << "jwt_inspector " << VERSION << "\n";
}

CLIOptions parse_args(int argc, char* argv[]) {
    CLIOptions opts;

    if (argc < 2)
        return opts; // defaults to Help

    // First non-program argument is the command.
    std::string first_arg = argv[1];
    opts.command = parse_command(first_arg);

    if (opts.command == Command::Help || opts.command == Command::Version)
        return opts;

    // Parse remaining arguments.
    bool token_set = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--file") {
            require_next_arg(i, argc, arg);
            opts.token_file = argv[++i];

        } else if (arg == "--wordlist") {
            require_next_arg(i, argc, arg);
            opts.wordlist = argv[++i];

        } else if (arg == "--threads") {
            require_next_arg(i, argc, arg);
            ++i;
            try {
                int val = std::stoi(argv[i]);
                if (val < 0)
                    throw std::runtime_error("--threads value must be non-negative");
                opts.threads = static_cast<unsigned int>(val);
            } catch (const std::invalid_argument&) {
                throw std::runtime_error("--threads requires a numeric argument, got: "
                                         + std::string(argv[i]));
            } catch (const std::out_of_range&) {
                throw std::runtime_error("--threads value out of range: "
                                         + std::string(argv[i]));
            }

        } else if (arg == "--charset") {
            require_next_arg(i, argc, arg);
            opts.charset = argv[++i];

        } else if (arg == "--max-length") {
            require_next_arg(i, argc, arg);
            ++i;
            try {
                long val = std::stol(argv[i]);
                if (val <= 0)
                    throw std::runtime_error("--max-length must be a positive integer");
                opts.max_length = static_cast<size_t>(val);
            } catch (const std::invalid_argument&) {
                throw std::runtime_error("--max-length requires a numeric argument, got: "
                                         + std::string(argv[i]));
            } catch (const std::out_of_range&) {
                throw std::runtime_error("--max-length value out of range: "
                                         + std::string(argv[i]));
            }

        } else if (arg == "--pubkey") {
            require_next_arg(i, argc, arg);
            opts.pubkey = argv[++i];

        } else if (arg == "--json") {
            opts.json_output = true;

        } else if (arg == "--help" || arg == "-h") {
            opts.command = Command::Help;
            return opts;

        } else if (arg == "--version" || arg == "-v") {
            opts.command = Command::Version;
            return opts;

        } else if (arg.rfind("--", 0) == 0) {
            throw std::runtime_error("Unknown option: " + arg);

        } else {
            // Positional argument = token string
            if (token_set)
                throw std::runtime_error("Unexpected positional argument: " + arg);
            opts.token = arg;
            token_set = true;
        }
    }

    // Resolve token from file if --file was given.
    if (opts.token_file.has_value()) {
        if (token_set)
            throw std::runtime_error(
                "Cannot specify both a positional token and --file");
        opts.token = read_first_line(opts.token_file.value());
    }

    // Auto-detect thread count when left at 0.
    if (opts.threads == 0) {
        unsigned int hw = std::thread::hardware_concurrency();
        opts.threads = (hw > 0) ? hw : 1;
    }

    return opts;
}
