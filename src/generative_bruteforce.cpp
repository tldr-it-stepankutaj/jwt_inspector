#include "jwt_bruteforce.hpp"
#include "jwt_utils.hpp"
#include "progress.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace jwt_inspector {

namespace {

const EVP_MD* evp_md_for_alg_gen(const std::string& alg) {
    if (alg == "HS256") return EVP_sha256();
    if (alg == "HS384") return EVP_sha384();
    if (alg == "HS512") return EVP_sha512();
    return nullptr;
}

size_t hash_size_for_alg_gen(const std::string& alg) {
    if (alg == "HS256") return 32;
    if (alg == "HS384") return 48;
    if (alg == "HS512") return 64;
    return 0;
}

/// Convert a linear index to a candidate string.
/// index 0..base-1 → single chars, base..base+base^2-1 → two chars, etc.
std::string index_to_candidate(size_t index, const std::string& charset) {
    size_t base = charset.size();
    std::string result;
    // Determine length: length 1 covers [0, base), length 2 covers [base, base+base^2), etc.
    size_t offset = 0;
    size_t span = base;
    size_t length = 1;
    while (index >= offset + span && length < 64) {
        offset += span;
        ++length;
        span *= base;
    }
    size_t remainder = index - offset;
    result.resize(length);
    for (size_t i = length; i > 0; --i) {
        result[i - 1] = charset[remainder % base];
        remainder /= base;
    }
    return result;
}

/// Total number of candidates for lengths 1..max_length with given charset.
size_t total_candidates(size_t charset_size, size_t max_length) {
    size_t total = 0;
    size_t power = 1;
    for (size_t len = 1; len <= max_length; ++len) {
        power *= charset_size;
        total += power;
    }
    return total;
}

void print_gen_result(const BruteforceResult& r, bool json_output) {
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

BruteforceResult generative_bruteforce(const std::string& token,
                                       const std::string& charset,
                                       size_t max_length,
                                       unsigned int num_threads,
                                       bool json_output) {
    BruteforceResult result;

    if (charset.empty() || max_length == 0) {
        throw std::runtime_error("Charset and max_length must be non-empty/non-zero");
    }

    auto parts = jwt_utils::split_token(token);
    std::string alg = jwt_utils::parse_header_alg(parts.header_b64);
    const EVP_MD* md = evp_md_for_alg_gen(alg);
    if (!md) {
        throw std::runtime_error("Unsupported HMAC algorithm: " + alg);
    }
    size_t expected_hash_size = hash_size_for_alg_gen(alg);
    auto expected_sig = jwt_utils::base64url_decode(parts.signature_b64);
    if (expected_sig.size() != expected_hash_size) {
        throw std::runtime_error("Signature size mismatch");
    }

    const std::string& msg = parts.header_payload;
    size_t total = total_candidates(charset.size(), max_length);

    if (!json_output) {
        std::cerr << "Generative bruteforce: charset=\"" << charset
                  << "\", max_length=" << max_length
                  << ", total_candidates=" << total << "\n";
    }

    if (num_threads == 0) {
        num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 4;
    }

    std::atomic<int> found_flag{0};
    std::string found_secret;
    std::mutex found_mutex;

    ProgressReporter progress(total, json_output);
    progress.start();

    auto start_time = std::chrono::high_resolution_clock::now();

    auto worker = [&](size_t from, size_t to) {
        unsigned char hmac_buf[EVP_MAX_MD_SIZE];
        unsigned int hmac_len = 0;

        for (size_t idx = from; idx < to; ++idx) {
            if (found_flag.load(std::memory_order_relaxed)) return;

            std::string candidate = index_to_candidate(idx, charset);
            HMAC(md, candidate.data(), static_cast<int>(candidate.size()),
                 reinterpret_cast<const unsigned char*>(msg.data()),
                 msg.size(), hmac_buf, &hmac_len);

            if (hmac_len == expected_hash_size &&
                std::memcmp(hmac_buf, expected_sig.data(), expected_hash_size) == 0) {
                std::lock_guard<std::mutex> lock(found_mutex);
                if (!found_flag.load()) {
                    found_secret = candidate;
                    found_flag.store(1, std::memory_order_release);
                }
                return;
            }
            progress.increment();
        }
    };

    std::vector<std::thread> threads;
    size_t chunk = total / num_threads;
    for (unsigned int t = 0; t < num_threads; ++t) {
        size_t from = t * chunk;
        size_t to = (t == num_threads - 1) ? total : from + chunk;
        threads.emplace_back(worker, from, to);
    }

    for (auto& t : threads) {
        t.join();
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    progress.stop();

    result.elapsed_sec = std::chrono::duration<double>(end_time - start_time).count();
    if (found_flag.load()) {
        result.found = true;
        result.secret = found_secret;
    }
    result.attempts = progress.attempts();
    result.hashes_per_sec = (result.elapsed_sec > 0)
                            ? static_cast<double>(result.attempts) / result.elapsed_sec
                            : 0.0;

    print_gen_result(result, json_output);
    return result;
}

} // namespace jwt_inspector
