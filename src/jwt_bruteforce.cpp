#include "jwt_bruteforce.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <stdexcept>
#include <OpenCL/opencl.h>
#include <vector>
#include <algorithm>
#include <iterator>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <cassert>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/types.h>

// ---- Base64URL decoding (simple, padding-aware) ----
std::string JWTBruteForcer::base64url_decode(const std::string& input) {
    std::string b64 = input;
    std::replace(b64.begin(), b64.end(), '-', '+');
    std::replace(b64.begin(), b64.end(), '_', '/');
    while (b64.size() % 4 != 0) {
        b64 += '=';
    }

    BIO* b64bio = BIO_new(BIO_f_base64());
    BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL);
    BIO* bio = BIO_new_mem_buf(b64.data(), static_cast<int>(b64.length()));
    bio = BIO_push(b64bio, bio);

    std::vector<char> buffer(b64.length());
    std::string::size_type decoded_len = BIO_read(bio, buffer.data(), static_cast<int>(b64.length()));
    BIO_free_all(bio);
    return {buffer.data(), decoded_len};
}

// ---- JWT Parser ----
void JWTBruteForcer::parse_token(const std::string& token) {
    std::stringstream ss(token);
    std::string part;
    std::vector<std::string> parts;

    while (std::getline(ss, part, '.')) {
        parts.push_back(part);
    }

    if (parts.size() != 3) {
        throw std::runtime_error("Invalid JWT format");
    }

    headerPayload = parts[0] + "." + parts[1];
    const std::string sig_str = parts[2];
    std::string decoded = base64url_decode(sig_str);
    decodedSignature.assign(decoded.begin(), decoded.end());
}

// ---- HMAC brute-force using OpenCL ----
void JWTBruteForcer::run(const std::string& token, const std::vector<std::string>& wordlist) {
    parse_token(token);

    std::cout << "\U0001F510 Token signature bytes: " << decodedSignature.size() << " bytes\n";
    std::cout << "\U0001F5BE Total secrets to test: " << wordlist.size() << "\n";

    // === OpenCL platform/device/context setup ===
    cl_platform_id platform_id = nullptr;
    cl_device_id device_id = nullptr;
    cl_context context = nullptr;
    cl_command_queue queue = nullptr;

    cl_int err;
    err = clGetPlatformIDs(1, &platform_id, nullptr);
    err |= clGetDeviceIDs(platform_id, CL_DEVICE_TYPE_GPU, 1, &device_id, nullptr);
    context = clCreateContext(nullptr, 1, &device_id, nullptr, nullptr, &err);
    queue = clCreateCommandQueue(context, device_id, 0, &err);

    char device_name[128];
    clGetDeviceInfo(device_id, CL_DEVICE_NAME, sizeof(device_name), device_name, nullptr);
    std::cout << "\U0001F5A5  OpenCL device: " << device_name << "\n";

    std::ifstream kernel_file("kernels/hmac_sha256.cl");
    std::string kernel_src((std::istreambuf_iterator<char>(kernel_file)), std::istreambuf_iterator<char>());
    const char* kernel_cstr = kernel_src.c_str();
    size_t kernel_size = kernel_src.size();

    cl_program program = clCreateProgramWithSource(context, 1, &kernel_cstr, &kernel_size, &err);
    err = clBuildProgram(program, 0, nullptr, nullptr, nullptr, nullptr);

    if (err != CL_SUCCESS) {
        char buffer[2048];
        clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, sizeof(buffer), buffer, nullptr);
        std::cerr << "❌ OpenCL build error:\n" << buffer << "\n";
        return;
    }

    cl_kernel kernel = clCreateKernel(program, "hmac_sha256_bruteforce", &err);

    constexpr int secret_len = 32;
    const int header_len = headerPayload.size();
    const int total = wordlist.size();

    std::vector<cl_uchar> secrets(total * secret_len, 0);
    for (int i = 0; i < total; ++i) {
        const auto& w = wordlist[i];
        memcpy(&secrets[i * secret_len], w.c_str(), std::min(static_cast<int>(w.size()), secret_len));
    }

    cl_mem buf_header = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, header_len, (void*)headerPayload.data(), &err);
    cl_mem buf_secrets = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, secrets.size(), secrets.data(), &err);
    cl_mem buf_signature = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, decodedSignature.size(), decodedSignature.data(), &err);

    int found_index = -1;
    cl_mem buf_found = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof(int), &found_index, &err);

    err |= clSetKernelArg(kernel, 0, sizeof(cl_mem), &buf_header);
    err |= clSetKernelArg(kernel, 1, sizeof(int), &header_len);
    err |= clSetKernelArg(kernel, 2, sizeof(cl_mem), &buf_secrets);
    err |= clSetKernelArg(kernel, 3, sizeof(int), &secret_len);
    err |= clSetKernelArg(kernel, 4, sizeof(int), &total);
    err |= clSetKernelArg(kernel, 5, sizeof(cl_mem), &buf_signature);
    err |= clSetKernelArg(kernel, 6, sizeof(cl_mem), &buf_found);

    std::cout << "🚀 Starting OpenCL brute-force...\n";

    auto t_start = std::chrono::high_resolution_clock::now();
    size_t global_size = total;
    err = clEnqueueNDRangeKernel(queue, kernel, 1, nullptr, &global_size, nullptr, 0, nullptr, nullptr);
    clFinish(queue);
    auto t_end = std::chrono::high_resolution_clock::now();

    double elapsed = std::chrono::duration<double>(t_end - t_start).count();

    clEnqueueReadBuffer(queue, buf_found, CL_TRUE, 0, sizeof(int), &found_index, 0, nullptr, nullptr);

    std::cout << "⏱  Time: " << std::fixed << std::setprecision(4) << elapsed << " sec\n";
    std::cout << "⚡ Hashes/sec: " << static_cast<size_t>(total / elapsed) << "\n";

    if (found_index >= 0 && found_index < total) {
        std::cout << "✅ Secret FOUND: \"" << wordlist[found_index] << "\" at index " << found_index << "\n";
    } else {
        std::cout << "❌ No matching secret found.\n";
    }

    // Cleanup
    clReleaseMemObject(buf_header);
    clReleaseMemObject(buf_secrets);
    clReleaseMemObject(buf_signature);
    clReleaseMemObject(buf_found);
    clReleaseKernel(kernel);
    clReleaseProgram(program);
    clReleaseCommandQueue(queue);
    clReleaseContext(context);
}
