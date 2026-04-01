#include "jwt_bruteforce.hpp"
#include "jwt_utils.hpp"
#include "progress.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace jwt_inspector {

namespace {

const EVP_MD* evp_md_for_alg(const std::string& alg) {
    if (alg == "HS256") return EVP_sha256();
    if (alg == "HS384") return EVP_sha384();
    if (alg == "HS512") return EVP_sha512();
    return nullptr;
}

size_t hash_size_for_alg(const std::string& alg) {
    if (alg == "HS256") return 32;
    if (alg == "HS384") return 48;
    if (alg == "HS512") return 64;
    return 0;
}

void print_result(const BruteforceResult& r, bool json_output) {
    if (json_output) {
        std::cout << "{\"found\":" << (r.found ? "true" : "false");
        if (r.found) std::cout << ",\"secret\":\"" << r.secret << "\"";
        std::cout << ",\"attempts\":" << r.attempts
                  << ",\"elapsed_sec\":" << r.elapsed_sec
                  << ",\"hashes_per_sec\":" << static_cast<size_t>(r.hashes_per_sec)
                  << "}\n";
    } else {
        std::cout << "Attempts: " << r.attempts << "\n";
        std::cout << "Time: " << r.elapsed_sec << " s\n";
        std::cout << "Speed: " << static_cast<size_t>(r.hashes_per_sec) << " h/s\n";
        if (r.found) {
            std::cout << "Secret FOUND: \"" << r.secret << "\"\n";
        } else {
            std::cout << "No matching secret found.\n";
        }
    }
}

} // anonymous namespace

BruteforceResult cpu_bruteforce(const std::string& token,
                                const std::vector<std::string>& wordlist,
                                unsigned int num_threads,
                                bool json_output) {
    BruteforceResult result;

    auto parts = jwt_utils::split_token(token);
    std::string alg = jwt_utils::parse_header_alg(parts.header_b64);
    const EVP_MD* md = evp_md_for_alg(alg);
    if (!md) {
        throw std::runtime_error("Unsupported HMAC algorithm: " + alg);
    }
    size_t expected_hash_size = hash_size_for_alg(alg);

    // Decode expected signature to raw bytes for direct comparison
    auto expected_sig = jwt_utils::base64url_decode(parts.signature_b64);
    if (expected_sig.size() != expected_hash_size) {
        throw std::runtime_error("Signature size mismatch: expected " +
                                 std::to_string(expected_hash_size) + " bytes, got " +
                                 std::to_string(expected_sig.size()));
    }

    const std::string& msg = parts.header_payload;

    if (num_threads == 0) {
        num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 4;
    }

    std::atomic<int> found_idx{-1};

    ProgressReporter progress(wordlist.size(), json_output);
    progress.start();

    auto start_time = std::chrono::high_resolution_clock::now();

    // Worker function
    auto worker = [&](size_t from, size_t to) {
        unsigned char hmac_buf[EVP_MAX_MD_SIZE];
        unsigned int hmac_len = 0;

        for (size_t i = from; i < to; ++i) {
            if (found_idx.load(std::memory_order_relaxed) >= 0) return;

            const std::string& candidate = wordlist[i];
            HMAC(md, candidate.data(), static_cast<int>(candidate.size()),
                 reinterpret_cast<const unsigned char*>(msg.data()),
                 msg.size(), hmac_buf, &hmac_len);

            if (hmac_len == expected_hash_size &&
                std::memcmp(hmac_buf, expected_sig.data(), expected_hash_size) == 0) {
                int expected = -1;
                found_idx.compare_exchange_strong(expected, static_cast<int>(i));
                return;
            }
            progress.increment();
        }
    };

    // Launch threads
    std::vector<std::thread> threads;
    size_t chunk = wordlist.size() / num_threads;
    for (unsigned int t = 0; t < num_threads; ++t) {
        size_t from = t * chunk;
        size_t to = (t == num_threads - 1) ? wordlist.size() : from + chunk;
        threads.emplace_back(worker, from, to);
    }

    for (auto& t : threads) {
        t.join();
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    progress.stop();

    result.elapsed_sec = std::chrono::duration<double>(end_time - start_time).count();
    int idx = found_idx.load();
    if (idx >= 0) {
        result.found = true;
        result.secret = wordlist[static_cast<size_t>(idx)];
    }
    result.attempts = progress.attempts();
    result.hashes_per_sec = (result.elapsed_sec > 0)
                            ? static_cast<double>(result.attempts) / result.elapsed_sec
                            : 0.0;

    print_result(result, json_output);
    return result;
}

} // namespace jwt_inspector
