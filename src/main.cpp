#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#include "jwt_bruteforce.hpp"

std::string read_token(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Cannot open token file: " + path);
    }

    std::string token;
    std::getline(file, token);
    return token;
}

std::vector<std::string> read_wordlist(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Cannot open wordlist: " + path);
    }

    std::vector<std::string> words;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            words.push_back(line);
        }
    }
    return words;
}

int main() {
    try {
        const std::string token = read_token("data/sample_token.txt");
        const std::vector<std::string> wordlist = read_wordlist("data/wordlist.txt");

        JWTBruteForcer jwt_brute_forcer;
        jwt_brute_forcer.run(token, wordlist);

    } catch (const std::exception& ex) {
        std::cerr << "❌ Error: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}