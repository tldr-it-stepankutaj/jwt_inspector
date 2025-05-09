#include "jwt_decoder.hpp"
#include <iostream>
#include <sstream>
#include <vector>
#include <fstream>
#include <algorithm>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>
#include <ctime>
#include <iomanip>
#include <limits>

#include <thread>
#include <atomic>
#include <chrono>

using json = nlohmann::json;

std::string JWTDecoder::base64url_decode(const std::string& input) {
    std::string b64 = input;
    std::replace(b64.begin(), b64.end(), '-', '+');
    std::replace(b64.begin(), b64.end(), '_', '/');
    while (b64.size() % 4 != 0) {
        b64 += '=';
    }

    if (b64.size() > std::numeric_limits<int>::max()) {
        std::cerr << "❌ Input too large for BIO_read.\n";
        return "";
    }

    const auto buffer = static_cast<char*>(malloc(b64.size()));
    memset(buffer, 0, b64.size());

    BIO* b64b = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new_mem_buf((void*)b64.c_str(), -1);
    bio = BIO_push(b64b, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int decoded_size = BIO_read(bio, buffer, static_cast<int>(b64.size()));
    std::string result(buffer, decoded_size);
    BIO_free_all(bio);
    free(buffer);
    return result;
}

std::string base64url_encode(const unsigned char* data, const size_t len) {
    if (len > std::numeric_limits<int>::max()) {
        std::cerr << "❌ Data too large for BIO_write.\n";
        return "";
    }

    BUF_MEM* buffer_ptr;

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data, static_cast<int>(len));
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &buffer_ptr);

    std::string b64_str(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(b64);

    // URL safe variant
    std::replace(b64_str.begin(), b64_str.end(), '+', '-');
    std::replace(b64_str.begin(), b64_str.end(), '/', '_');
    b64_str.erase(std::remove(b64_str.begin(), b64_str.end(), '='), b64_str.end());

    return b64_str;
}

std::string format_time(long timestamp) {
    auto t = static_cast<time_t>(timestamp);
    const std::tm* tm = std::gmtime(&t);
    char buffer[30];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm);
    return {buffer};
}

void JWTDecoder::decode(const std::string& token) {
    std::stringstream ss(token);
    std::string part;
    std::vector<std::string> parts;

    while (std::getline(ss, part, '.')) {
        parts.push_back(part);
    }

    if (parts.size() != 3) {
        std::cerr << "❌ Invalid JWT format.\n";
        return;
    }

    std::string header_str = base64url_decode(parts[0]);
    std::string payload_str = base64url_decode(parts[1]);
    std::string signature = parts[2];

    json header = json::parse(header_str);
    json payload = json::parse(payload_str);

    std::cout << "📦 Loaded JWT token:\n" << token << "\n\n";

    std::cout << "🔐 Header:\n";
    std::cout << "Algorythm: " << header["alg"] << "\n\n";

    std::cout << "📄 Payload:\n";
    std::cout << "Subject: " << payload["sub"] << "\n";
    std::cout << "Roles: " << payload["roles"] << "\n";
    std::cout << "ID: " << payload["id"] << "\n";
    std::cout << "Issuer: " << payload["iss"] << "\n";

    if (payload.contains("iat"))
        std::cout << "Created: " << payload["iat"] << " /// " << format_time(payload["iat"]) << "\n";
    if (payload.contains("exp"))
        std::cout << "Expired: " << payload["exp"] << " /// " << format_time(payload["exp"]) << "\n";

    std::cout << "\n✍️ Signature (raw base64url):\n" << signature << "\n";
}

void JWTDecoder::bruteforce_secret(const std::string& token, const std::string& wordlist_path) {
    std::stringstream ss(token);
    std::string part;
    std::vector<std::string> parts;

    while (std::getline(ss, part, '.')) {
        parts.push_back(part);
    }

    if (parts.size() != 3) {
        std::cerr << "❌ Invalid JWT format.\n";
        return;
    }

    std::string header_payload = parts[0] + "." + parts[1];
    std::string token_signature = parts[2];

    std::ifstream wordlist(wordlist_path);
    if (!wordlist.is_open()) {
        std::cerr << "❌ Cannot open wordlist: " << wordlist_path << "\n";
        return;
    }

    std::string candidate;
    while (std::getline(wordlist, candidate)) {
        unsigned char result[EVP_MAX_MD_SIZE];
        unsigned int len = 0;

        HMAC(EVP_sha256(), candidate.c_str(), static_cast<int>(candidate.length()),
             reinterpret_cast<const unsigned char*>(header_payload.c_str()), static_cast<int>(header_payload.length()),
             result, &len);

        std::string candidate_signature = base64url_encode(result, len);

        if (candidate_signature == token_signature) {
            std::cout << "✅ Secret FOUND: \"" << candidate << "\"\n";
            return;
        }
    }

    std::cout << "❌ No secret matched.\n";
}

void JWTDecoder::bruteforce_secret_multithreaded(const std::string& token, const std::string& wordlist_path, unsigned int num_threads) {
    std::stringstream ss(token);
    std::string part;
    std::vector<std::string> parts;

    while (std::getline(ss, part, '.')) {
        parts.push_back(part);
    }

    if (parts.size() != 3) {
        std::cerr << "❌ Invalid JWT format.\n";
        return;
    }

    std::string header_payload = parts[0] + "." + parts[1];
    std::string token_signature = parts[2];

    // Load wordlist into vector
    std::ifstream wordlist(wordlist_path);
    if (!wordlist.is_open()) {
        std::cerr << "❌ Cannot open wordlist: " << wordlist_path << "\n";
        return;
    }

    std::vector<std::string> secrets;
    std::string line;
    while (std::getline(wordlist, line)) {
        if (!line.empty()) {
            secrets.push_back(line);
        }
    }

    if (secrets.empty()) {
        std::cerr << "❌ Wordlist is empty.\n";
        return;
    }

    std::atomic<bool> found{false};
    std::atomic<size_t> attempts{0};
    std::string found_secret;

    const auto start_time = std::chrono::high_resolution_clock::now();

    // Thread function
    auto worker = [&](int tid, size_t from, size_t to) {
        for (size_t i = from; i < to && !found; ++i) {
            const std::string& candidate = secrets[i];
            unsigned char result[EVP_MAX_MD_SIZE];
            unsigned int len = 0;

            HMAC(EVP_sha256(), candidate.c_str(), static_cast<int>(candidate.length()),
                 reinterpret_cast<const unsigned char*>(header_payload.c_str()), static_cast<int>(header_payload.length()),
                 result, &len);

            std::string candidate_signature = base64url_encode(result, len);
            ++attempts;

            if (candidate_signature == token_signature) {
                found_secret = candidate;
                found = true;
                return;
            }
        }
    };

    // Launch threads
    std::vector<std::thread> threads;
    size_t chunk = secrets.size() / num_threads;

    for (int t = 0; t < num_threads; ++t) {
        size_t from = t * chunk;
        size_t to = (t == num_threads - 1) ? secrets.size() : from + chunk;
        threads.emplace_back(worker, t, from, to);
    }

    // Wait for all threads
    for (auto& t : threads) {
        t.join();
    }

    const auto end_time = std::chrono::high_resolution_clock::now();
    double seconds = std::chrono::duration<double>(end_time - start_time).count();
    double rate = static_cast<double>(attempts) / seconds;

    std::cout << "\n🔢 Total attempts: " << attempts << "\n";
    std::cout << "⏱  Time elapsed: " << std::fixed << std::setprecision(3) << seconds << " s\n";
    std::cout << "⚡ Hashes/sec: " << static_cast<size_t>(rate) << "\n";

    if (found) {
        std::cout << "✅ Secret FOUND: \"" << found_secret << "\"\n";
    } else {
        std::cout << "❌ No secret matched.\n";
    }
}