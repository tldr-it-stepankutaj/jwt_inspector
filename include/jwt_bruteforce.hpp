#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace jwt_inspector {

struct BruteforceResult {
    bool found = false;
    std::string secret;
    size_t attempts = 0;
    double elapsed_sec = 0.0;
    double hashes_per_sec = 0.0;
};

/// CPU dictionary bruteforce using wordlist.
BruteforceResult cpu_bruteforce(const std::string& token,
                                const std::vector<std::string>& wordlist,
                                unsigned int num_threads,
                                bool json_output = false);

/// GPU dictionary bruteforce using OpenCL.
BruteforceResult gpu_bruteforce(const std::string& token,
                                const std::vector<std::string>& wordlist,
                                bool json_output = false);

/// Generative bruteforce: tries all combinations of charset up to max_length.
BruteforceResult generative_bruteforce(const std::string& token,
                                       const std::string& charset,
                                       size_t max_length,
                                       unsigned int num_threads,
                                       bool json_output = false);

} // namespace jwt_inspector
