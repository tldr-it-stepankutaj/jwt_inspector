#include "cli.hpp"
#include "jwt_bruteforce.hpp"
#include "jwt_decoder.hpp"
#include "jwt_forge.hpp"
#include "jwt_utils.hpp"
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

// Exit codes. Documented in the --help output and README so scripts/CI can
// rely on them (e.g. "fail the build if jwt_inspector bruteforce finds a
// secret"), instead of always getting 0 back regardless of outcome.
namespace exit_code {
constexpr int kSuccess = 0;        // secret found / signature valid / decode ok
constexpr int kError = 1;          // bad arguments, file not found, malformed token, ...
constexpr int kNotFound = 2;       // ran to completion, but the secret was NOT found
constexpr int kSignatureInvalid = 3; // ran to completion, but the signature is NOT valid
} // namespace exit_code

int main(int argc, char* argv[]) {
    try {
        CLIOptions opts = parse_args(argc, argv);

        switch (opts.command) {
            case Command::Help:
                print_usage();
                return exit_code::kSuccess;

            case Command::Version:
                print_version();
                return exit_code::kSuccess;

            case Command::Decode: {
                if (opts.token.empty()) {
                    throw std::runtime_error("No token provided. Use a positional arg or --file.");
                }
                jwt_inspector::decode_token(opts.token, opts.json_output);
                return exit_code::kSuccess;
            }

            case Command::CpuBruteforce: {
                if (opts.token.empty()) {
                    throw std::runtime_error("No token provided.");
                }
                if (!opts.wordlist.has_value()) {
                    throw std::runtime_error("--wordlist is required for bruteforce.");
                }
                auto wordlist = read_wordlist(opts.wordlist.value());
                auto result = jwt_inspector::cpu_bruteforce(opts.token, wordlist, opts.threads, opts.json_output);
                return result.found ? exit_code::kSuccess : exit_code::kNotFound;
            }

            case Command::GpuBruteforce: {
                if (opts.token.empty()) {
                    throw std::runtime_error("No token provided.");
                }
                if (!opts.wordlist.has_value()) {
                    throw std::runtime_error("--wordlist is required for gpu-bruteforce.");
                }
                auto wordlist = read_wordlist(opts.wordlist.value());
                auto result = jwt_inspector::gpu_bruteforce(opts.token, wordlist, opts.json_output);
                return result.found ? exit_code::kSuccess : exit_code::kNotFound;
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
                auto result = jwt_inspector::generative_bruteforce(opts.token, opts.charset, opts.max_length,
                                                                    opts.threads, opts.json_output);
                return result.found ? exit_code::kSuccess : exit_code::kNotFound;
            }

            case Command::Verify: {
                if (opts.token.empty()) {
                    throw std::runtime_error("No token provided.");
                }
                if (!opts.pubkey.has_value()) {
                    throw std::runtime_error("--pubkey is required for verify.");
                }
                std::string pubkey = jwt_utils::read_whole_file(opts.pubkey.value());
                auto result = jwt_inspector::verify_token(opts.token, pubkey, opts.json_output);
                return result.valid ? exit_code::kSuccess : exit_code::kSignatureInvalid;
            }

            case Command::Forge: {
                int mode_count = (opts.forge_secret.has_value() ? 1 : 0) +
                                  (opts.forge_confusion_pubkey.has_value() ? 1 : 0) +
                                  (opts.forge_none ? 1 : 0);
                if (mode_count != 1) {
                    throw std::runtime_error(
                        "forge requires exactly one of --secret, --confusion-pubkey, or --none.");
                }
                if (opts.forge_none && opts.forge_alg_set) {
                    throw std::runtime_error("--alg has no effect with --none (alg is always \"none\").");
                }

                jwt_inspector::ForgeOptions fopts;
                fopts.base_token = opts.token;
                fopts.hmac_alg = opts.forge_alg;
                fopts.claims_file = opts.claims_file;

                if (opts.forge_secret.has_value()) {
                    fopts.mode = jwt_inspector::ForgeSigningMode::Secret;
                    fopts.secret = opts.forge_secret.value();
                } else if (opts.forge_confusion_pubkey.has_value()) {
                    fopts.mode = jwt_inspector::ForgeSigningMode::ConfusionPubkey;
                    fopts.confusion_pubkey_path = opts.forge_confusion_pubkey.value();
                } else {
                    fopts.mode = jwt_inspector::ForgeSigningMode::None;
                }

                auto result = jwt_inspector::forge_token(fopts);

                if (opts.json_output) {
                    std::cout << R"({"token":")" << result.token
                              << R"(","algorithm":")" << result.algorithm
                              << R"(","confusion_attack":)" << (result.confusion_attack ? "true" : "false")
                              << "}\n";
                } else {
                    if (result.confusion_attack) {
                        std::cerr << "Forged " << result.algorithm
                                  << " token using the public key as the HMAC secret "
                                     "(RS/ES -> HS confusion attack):\n";
                    } else if (result.algorithm == "none") {
                        std::cerr << "Forged unsigned \"alg\":\"none\" token:\n";
                    } else {
                        std::cerr << "Forged " << result.algorithm << " token:\n";
                    }
                    std::cout << result.token << "\n";
                }
                return exit_code::kSuccess;
            }
        }

    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return exit_code::kError;
    }

    return exit_code::kSuccess;
}
