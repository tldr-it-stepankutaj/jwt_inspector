#ifndef JWT_BRUTEFORCE_HPP
#define JWT_BRUTEFORCE_HPP

#include <string>
#include <vector>

class JWTBruteForcer {
public:
    void run(const std::string& token, const std::vector<std::string>& wordlist);

private:
    std::string headerPayload;
    std::string tokenSignature;

    std::vector<unsigned char> decodedSignature;

    void parse_token(const std::string& token);
    static std::string base64url_decode(const std::string& input);
};

#endif // JWT_BRUTEFORCE_HPP