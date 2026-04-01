#include "cli.hpp"
#include "jwt_bruteforce.hpp"
#include "jwt_decoder.hpp"
#include "jwt_verifier.hpp"

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static std::vector<std::string> read_wordlist(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Cannot open wordlist: " + path);
    }
    std::vector<std::string> words;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            words.push_back(std::move(line));
        }
    }
    return words;
}

static std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

int main(int argc, char* argv[]) {
    try {
        CLIOptions opts = parse_args(argc, argv);

        switch (opts.command) {
            case Command::Help:
                print_usage();
                return 0;

            case Command::Version:
                print_version();
                return 0;

            case Command::Decode: {
                if (opts.token.empty()) {
                    throw std::runtime_error("No token provided. Use a positional arg or --file.");
                }
                jwt_inspector::decode_token(opts.token, opts.json_output);
                break;
            }

            case Command::CpuBruteforce: {
                if (opts.token.empty()) {
                    throw std::runtime_error("No token provided.");
                }
                if (!opts.wordlist.has_value()) {
                    throw std::runtime_error("--wordlist is required for bruteforce.");
                }
                auto wordlist = read_wordlist(opts.wordlist.value());
                jwt_inspector::cpu_bruteforce(opts.token, wordlist, opts.threads, opts.json_output);
                break;
            }

            case Command::GpuBruteforce: {
                if (opts.token.empty()) {
                    throw std::runtime_error("No token provided.");
                }
                if (!opts.wordlist.has_value()) {
                    throw std::runtime_error("--wordlist is required for gpu-bruteforce.");
                }
                auto wordlist = read_wordlist(opts.wordlist.value());
                jwt_inspector::gpu_bruteforce(opts.token, wordlist, opts.json_output);
                break;
            }

            case Command::Generate: {
                if (opts.token.empty()) {
                    throw std::runtime_error("No token provided.");
                }
                if (opts.charset.empty()) {
                    throw std::runtime_error("--charset is required for generate.");
                }
                if (opts.max_length == 0) {
                    throw std::runtime_error("--max-length is required for generate.");
                }
                jwt_inspector::generative_bruteforce(opts.token, opts.charset, opts.max_length,
                                                     opts.threads, opts.json_output);
                break;
            }

            case Command::Verify: {
                if (opts.token.empty()) {
                    throw std::runtime_error("No token provided.");
                }
                if (!opts.pubkey.has_value()) {
                    throw std::runtime_error("--pubkey is required for verify.");
                }
                std::string pubkey = read_file(opts.pubkey.value());
                jwt_inspector::verify_token(opts.token, pubkey, opts.json_output);
                break;
            }
        }

    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
