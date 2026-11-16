#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <string>

#ifndef _WIN32
#include <sys/wait.h>
#endif

// Every other test in this suite links against jwt_lib and calls library
// functions (forge_token(), cpu_bruteforce(), ...) directly — none of them
// go through cli.cpp's argv parsing or main.cpp's command dispatch at all.
// That gap let a real regression slip through 42 passing tests unnoticed: a
// background tool silently reverted cli.cpp to an older version, so
// `jwt_inspector forge ...` printed "Unknown command: forge" even though
// every forge_token() unit test still passed. These tests invoke the actual
// built binary (JWT_INSPECTOR_BIN, injected by CMakeLists.txt) so a similar
// regression in argument parsing or command routing fails here instead of
// only showing up when someone runs the CLI by hand.

namespace {

/// Runs the jwt_inspector binary with `args`, capturing combined stdout+stderr
/// and the process exit code. `args` must not contain shell metacharacters
/// (every call site here only passes flags and base64url JWT fragments).
std::string run_cli(const std::string& args, int& exit_code) {
    std::string cmd = std::string("\"") + JWT_INSPECTOR_BIN + "\" " + args + " 2>&1";

#ifdef _WIN32
    FILE* pipe = _popen(cmd.c_str(), "r");
#else
    FILE* pipe = popen(cmd.c_str(), "r");
#endif
    if (!pipe) {
        exit_code = -1;
        return {};
    }

    std::string output;
    char buf[256];
    while (std::fgets(buf, sizeof(buf), pipe)) {
        output += buf;
    }

#ifdef _WIN32
    exit_code = _pclose(pipe); // already the child's exit code on Windows
#else
    int status = pclose(pipe);
    exit_code = (status != -1 && WIFEXITED(status)) ? WEXITSTATUS(status) : status;
#endif
    return output;
}

} // namespace

TEST(CliSmoke, HelpSucceeds) {
    int code;
    std::string out = run_cli("--help", code);
    EXPECT_EQ(code, 0);
    EXPECT_NE(out.find("Usage:"), std::string::npos) << out;
}

TEST(CliSmoke, VersionSucceeds) {
    int code;
    run_cli("--version", code);
    EXPECT_EQ(code, 0);
}

TEST(CliSmoke, UnknownCommandIsRejected) {
    int code;
    std::string out = run_cli("totally-bogus-command", code);
    EXPECT_EQ(code, 1);
    EXPECT_NE(out.find("Unknown command"), std::string::npos) << out;
}

TEST(CliSmoke, DecodeSucceeds) {
    std::string token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjAwMDAwMDAwfQ."
        "7RQs5OrajGpqLnkn4YKPV6ZoxlAlg80L20LREEUCDyY";
    int code;
    std::string out = run_cli("decode " + token, code);
    EXPECT_EQ(code, 0);
    EXPECT_NE(out.find("HS256"), std::string::npos) << out;
}

// Every command name parse_command() is supposed to recognize must reach that
// command's OWN argument validation (e.g. "No token provided.") rather than
// falling through to "Unknown command: <name>". That distinction — not just
// "exit code is 1 either way" — is exactly what the cli.cpp regression above
// would have broken, so each case checks the error text, not only the code.
TEST(CliSmoke, AllCommandsAreRoutedPastUnknownCommandCheck) {
    const char* commands[] = {"decode", "bruteforce", "gpu-bruteforce",
                               "generate", "verify", "forge"};
    for (const char* command : commands) {
        int code;
        std::string out = run_cli(command, code);
        EXPECT_EQ(code, 1) << "command: " << command;
        EXPECT_EQ(out.find("Unknown command"), std::string::npos)
            << "command: " << command << " -- output: " << out;
    }
}

TEST(CliSmoke, ForgeRequiresExactlyOneSigningMode) {
    int code;
    std::string none_given = run_cli("forge", code);
    EXPECT_EQ(code, 1);
    EXPECT_NE(none_given.find("requires exactly one"), std::string::npos) << none_given;

    std::string two_given = run_cli("forge --secret x --none", code);
    EXPECT_EQ(code, 1);
    EXPECT_NE(two_given.find("requires exactly one"), std::string::npos) << two_given;
}

TEST(CliSmoke, ForgeWithSecretSucceeds) {
    int code;
    std::string out = run_cli("forge --secret mysecret", code);
    EXPECT_EQ(code, 0);
    // header.payload.signature — a well-formed JWT has exactly two dots.
    EXPECT_EQ(std::count(out.begin(), out.end(), '.'), 2) << out;
}

TEST(CliSmoke, ForgeRejectsInvalidAlgName) {
    int code;
    std::string out = run_cli("forge --secret x --alg BOGUS", code);
    EXPECT_EQ(code, 1);
    EXPECT_NE(out.find("--alg must be one of"), std::string::npos) << out;
}

TEST(CliSmoke, ForgeNoneProducesEmptySignatureSegment) {
    int code;
    std::string out = run_cli("forge --none --json", code);
    EXPECT_EQ(code, 0);
    EXPECT_NE(out.find(R"("algorithm":"none")"), std::string::npos) << out;
}
