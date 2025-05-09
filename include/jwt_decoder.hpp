#ifndef JWT_DECODER_HPP
#define JWT_DECODER_HPP

#include <string>

class JWTDecoder {
public:
    static void decode(const std::string& token);
    static void bruteforce_secret(const std::string& token, const std::string& wordlist_path);
    static void bruteforce_secret_multithreaded(const std::string& token, const std::string& wordlist_path, unsigned int num_threads);

private:
    static std::string base64url_decode(const std::string& input);
};

#endif