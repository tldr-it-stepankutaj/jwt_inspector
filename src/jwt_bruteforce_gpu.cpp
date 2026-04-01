#include "jwt_bruteforce.hpp"
#include "jwt_utils.hpp"
#include "progress.hpp"

#include <iostream>
#include <fstream>
#include <chrono>
#include <cstring>
#include <algorithm>
#include <stdexcept>

#ifdef HAS_OPENCL
#include "opencl_context.hpp"
#endif

namespace jwt_inspector {

namespace {

void print_gpu_result(const BruteforceResult& r, bool json_output) {
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

std::string find_kernel_file() {
    // Try several paths relative to the binary
    const char* paths[] = {
        "kernels/hmac_sha256.cl",
        "../kernels/hmac_sha256.cl",
        "../share/jwt_inspector/kernels/hmac_sha256.cl",
    };
    for (auto& p : paths) {
        std::ifstream f(p);
        if (f.good()) return p;
    }
    throw std::runtime_error("Cannot find kernel file hmac_sha256.cl");
}

} // anonymous namespace

#ifdef HAS_OPENCL

BruteforceResult gpu_bruteforce(const std::string& token,
                                const std::vector<std::string>& wordlist,
                                bool json_output) {
    BruteforceResult result;

    auto parts = jwt_utils::split_token(token);
    std::string alg = jwt_utils::parse_header_alg(parts.header_b64);
    if (alg != "HS256") {
        throw std::runtime_error("GPU bruteforce currently supports HS256 only, got: " + alg);
    }

    auto expected_sig = jwt_utils::base64url_decode(parts.signature_b64);
    if (expected_sig.size() != 32) {
        throw std::runtime_error("Expected 32-byte signature for HS256, got " +
                                 std::to_string(expected_sig.size()));
    }

    const std::string& msg = parts.header_payload;
    const int header_len = static_cast<int>(msg.size());
    const int total = static_cast<int>(wordlist.size());

    // Compute max secret length from wordlist
    size_t max_secret_len = 0;
    for (auto& w : wordlist) {
        max_secret_len = std::max(max_secret_len, w.size());
    }
    if (max_secret_len == 0) {
        throw std::runtime_error("Wordlist is empty");
    }
    // Clamp to 64 (HMAC key block size — longer keys get hashed first,
    // but for simplicity we cap at 64 for the kernel)
    if (max_secret_len > 64) max_secret_len = 64;
    const int max_slen = static_cast<int>(max_secret_len);

    // Initialize OpenCL
    CLContext ctx;
    if (!json_output) {
        std::cerr << "OpenCL device: " << ctx.device_name() << "\n";
    }

    // Load kernel source
    std::string kernel_path = find_kernel_file();
    std::ifstream kernel_file(kernel_path);
    std::string kernel_src((std::istreambuf_iterator<char>(kernel_file)),
                            std::istreambuf_iterator<char>());

    cl_program program = ctx.build_program(kernel_src);
    CLKernel kernel(program, "hmac_sha256_bruteforce");
    clReleaseProgram(program); // kernel holds a reference

    // Batch processing
    constexpr int BATCH_SIZE = 65536;
    int found_index = -1;

    ProgressReporter progress(static_cast<size_t>(total), json_output);
    progress.start();
    auto start_time = std::chrono::high_resolution_clock::now();

    // Header payload buffer (constant across batches)
    CLBuffer buf_header(ctx.context(), CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                        static_cast<size_t>(header_len),
                        const_cast<char*>(msg.data()));

    // Expected signature buffer
    CLBuffer buf_sig(ctx.context(), CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                     expected_sig.size(), expected_sig.data());

    for (int batch_start = 0; batch_start < total && found_index < 0; batch_start += BATCH_SIZE) {
        int batch_end = std::min(batch_start + BATCH_SIZE, total);
        int batch_count = batch_end - batch_start;

        // Pack secrets and lengths
        std::vector<uint8_t> packed_secrets(static_cast<size_t>(batch_count * max_slen), 0);
        std::vector<int> lengths(static_cast<size_t>(batch_count));

        for (int i = 0; i < batch_count; ++i) {
            const auto& w = wordlist[static_cast<size_t>(batch_start + i)];
            int copy_len = static_cast<int>(std::min(w.size(), static_cast<size_t>(max_slen)));
            std::memcpy(&packed_secrets[static_cast<size_t>(i * max_slen)],
                        w.data(), static_cast<size_t>(copy_len));
            lengths[static_cast<size_t>(i)] = copy_len;
        }

        CLBuffer buf_secrets(ctx.context(), CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                             packed_secrets.size(), packed_secrets.data());
        CLBuffer buf_lengths(ctx.context(), CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                             lengths.size() * sizeof(int), lengths.data());

        int batch_found = -1;
        CLBuffer buf_found(ctx.context(), CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
                           sizeof(int), &batch_found);

        kernel.set_arg(0, buf_header);
        kernel.set_arg<int>(1, header_len);
        kernel.set_arg(2, buf_secrets);
        kernel.set_arg<int>(3, max_slen);
        kernel.set_arg(4, buf_lengths);
        kernel.set_arg<int>(5, batch_count);
        kernel.set_arg(6, buf_sig);
        kernel.set_arg(7, buf_found);

        size_t global_size = static_cast<size_t>(batch_count);
        cl_int err = clEnqueueNDRangeKernel(ctx.queue(), kernel.get(), 1, nullptr,
                                             &global_size, nullptr, 0, nullptr, nullptr);
        if (err != CL_SUCCESS) {
            throw std::runtime_error("clEnqueueNDRangeKernel failed (error " +
                                     std::to_string(err) + ")");
        }
        clFinish(ctx.queue());

        clEnqueueReadBuffer(ctx.queue(), buf_found.get(), CL_TRUE, 0,
                            sizeof(int), &batch_found, 0, nullptr, nullptr);

        progress.increment(static_cast<size_t>(batch_count));

        if (batch_found >= 0) {
            found_index = batch_start + batch_found;
        }
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    progress.stop();

    result.elapsed_sec = std::chrono::duration<double>(end_time - start_time).count();
    result.attempts = progress.attempts();
    result.hashes_per_sec = (result.elapsed_sec > 0)
                            ? static_cast<double>(result.attempts) / result.elapsed_sec
                            : 0.0;

    if (found_index >= 0 && found_index < total) {
        result.found = true;
        result.secret = wordlist[static_cast<size_t>(found_index)];
    }

    print_gpu_result(result, json_output);
    return result;
}

#else // !HAS_OPENCL

BruteforceResult gpu_bruteforce(const std::string& /*token*/,
                                const std::vector<std::string>& /*wordlist*/,
                                bool /*json_output*/) {
    throw std::runtime_error("GPU bruteforce not available: built without OpenCL support. "
                             "Rebuild with -DENABLE_OPENCL=ON");
}

#endif // HAS_OPENCL

} // namespace jwt_inspector
