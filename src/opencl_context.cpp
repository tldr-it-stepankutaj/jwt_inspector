#ifdef HAS_OPENCL

#include "opencl_context.hpp"

#include <vector>

// ---------------------------------------------------------------------------
// CLContext
// ---------------------------------------------------------------------------

CLContext::CLContext() {
    cl_uint num_platforms = 0;
    cl_int err = clGetPlatformIDs(0, nullptr, &num_platforms);
    if (err != CL_SUCCESS || num_platforms == 0)
        throw std::runtime_error("No OpenCL platforms found");

    std::vector<cl_platform_id> platforms(num_platforms);
    err = clGetPlatformIDs(num_platforms, platforms.data(), nullptr);
    if (err != CL_SUCCESS)
        throw std::runtime_error("Failed to retrieve OpenCL platform IDs");

    // Try GPU first, then fall back to CPU
    bool found = false;
    for (auto plat : platforms) {
        err = clGetDeviceIDs(plat, CL_DEVICE_TYPE_GPU, 1, &device_, nullptr);
        if (err == CL_SUCCESS) {
            platform_ = plat;
            found = true;
            break;
        }
    }

    if (!found) {
        for (auto plat : platforms) {
            err = clGetDeviceIDs(plat, CL_DEVICE_TYPE_CPU, 1, &device_, nullptr);
            if (err == CL_SUCCESS) {
                platform_ = plat;
                found = true;
                break;
            }
        }
    }

    if (!found)
        throw std::runtime_error("No suitable OpenCL device found (tried GPU and CPU)");

    context_ = clCreateContext(nullptr, 1, &device_, nullptr, nullptr, &err);
    if (err != CL_SUCCESS)
        throw std::runtime_error("Failed to create OpenCL context (error " + std::to_string(err) + ")");

#ifdef CL_VERSION_2_0
    queue_ = clCreateCommandQueueWithProperties(context_, device_, nullptr, &err);
#else
    queue_ = clCreateCommandQueue(context_, device_, 0, &err);
#endif
    if (err != CL_SUCCESS) {
        clReleaseContext(context_);
        context_ = nullptr;
        throw std::runtime_error("Failed to create OpenCL command queue (error " + std::to_string(err) + ")");
    }
}

CLContext::~CLContext() {
    if (queue_)   clReleaseCommandQueue(queue_);
    if (context_) clReleaseContext(context_);
}

cl_program CLContext::build_program(const std::string& source) const {
    const char* src = source.c_str();
    size_t len = source.size();
    cl_int err;

    cl_program program = clCreateProgramWithSource(context_, 1, &src, &len, &err);
    if (err != CL_SUCCESS)
        throw std::runtime_error("Failed to create OpenCL program from source (error " + std::to_string(err) + ")");

    err = clBuildProgram(program, 1, &device_, nullptr, nullptr, nullptr);
    if (err != CL_SUCCESS) {
        size_t log_size = 0;
        clGetProgramBuildInfo(program, device_, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
        std::string build_log(log_size, '\0');
        clGetProgramBuildInfo(program, device_, CL_PROGRAM_BUILD_LOG, log_size, &build_log[0], nullptr);
        clReleaseProgram(program);
        throw std::runtime_error("OpenCL program build failed:\n" + build_log);
    }

    return program;
}

std::string CLContext::device_name() const {
    size_t name_size = 0;
    clGetDeviceInfo(device_, CL_DEVICE_NAME, 0, nullptr, &name_size);
    std::string name(name_size, '\0');
    clGetDeviceInfo(device_, CL_DEVICE_NAME, name_size, &name[0], nullptr);
    while (!name.empty() && name.back() == '\0')
        name.pop_back();
    return name;
}

// ---------------------------------------------------------------------------
// CLBuffer
// ---------------------------------------------------------------------------

CLBuffer::CLBuffer(cl_context ctx, cl_mem_flags flags, size_t size, void* host_ptr) {
    cl_int err;
    mem_ = clCreateBuffer(ctx, flags, size, host_ptr, &err);
    if (err != CL_SUCCESS)
        throw std::runtime_error("Failed to create OpenCL buffer (error " + std::to_string(err) + ")");
}

CLBuffer::~CLBuffer() {
    if (mem_) clReleaseMemObject(mem_);
}

CLBuffer::CLBuffer(CLBuffer&& other) noexcept : mem_(other.mem_) {
    other.mem_ = nullptr;
}

CLBuffer& CLBuffer::operator=(CLBuffer&& other) noexcept {
    if (this != &other) {
        if (mem_) clReleaseMemObject(mem_);
        mem_ = other.mem_;
        other.mem_ = nullptr;
    }
    return *this;
}

// ---------------------------------------------------------------------------
// CLKernel
// ---------------------------------------------------------------------------

CLKernel::CLKernel(cl_program program, const char* name) {
    cl_int err;
    kernel_ = clCreateKernel(program, name, &err);
    if (err != CL_SUCCESS)
        throw std::runtime_error(std::string("Failed to create OpenCL kernel '") + name + "' (error " + std::to_string(err) + ")");
}

CLKernel::~CLKernel() {
    if (kernel_) clReleaseKernel(kernel_);
}

CLKernel::CLKernel(CLKernel&& other) noexcept : kernel_(other.kernel_) {
    other.kernel_ = nullptr;
}

CLKernel& CLKernel::operator=(CLKernel&& other) noexcept {
    if (this != &other) {
        if (kernel_) clReleaseKernel(kernel_);
        kernel_ = other.kernel_;
        other.kernel_ = nullptr;
    }
    return *this;
}

void CLKernel::set_arg(cl_uint index, const CLBuffer& buf) {
    cl_mem m = buf.get();
    cl_int err = clSetKernelArg(kernel_, index, sizeof(cl_mem), &m);
    if (err != CL_SUCCESS)
        throw std::runtime_error("Failed to set kernel arg " + std::to_string(index));
}

// ---------------------------------------------------------------------------
// CLProgram
// ---------------------------------------------------------------------------

CLProgram::CLProgram(const CLContext& ctx, const std::string& source) {
    const char* src = source.c_str();
    size_t len = source.size();
    cl_int err;

    program_ = clCreateProgramWithSource(ctx.context(), 1, &src, &len, &err);
    if (err != CL_SUCCESS)
        throw std::runtime_error("Failed to create OpenCL program from source (error " + std::to_string(err) + ")");

    cl_device_id dev = ctx.device();
    err = clBuildProgram(program_, 1, &dev, nullptr, nullptr, nullptr);
    if (err != CL_SUCCESS) {
        size_t log_size = 0;
        clGetProgramBuildInfo(program_, dev, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
        std::string build_log(log_size, '\0');
        clGetProgramBuildInfo(program_, dev, CL_PROGRAM_BUILD_LOG, log_size, &build_log[0], nullptr);
        clReleaseProgram(program_);
        program_ = nullptr;
        throw std::runtime_error("OpenCL program build failed:\n" + build_log);
    }
}

CLProgram::~CLProgram() {
    if (program_) clReleaseProgram(program_);
}

CLProgram::CLProgram(CLProgram&& other) noexcept : program_(other.program_) {
    other.program_ = nullptr;
}

CLProgram& CLProgram::operator=(CLProgram&& other) noexcept {
    if (this != &other) {
        if (program_) clReleaseProgram(program_);
        program_ = other.program_;
        other.program_ = nullptr;
    }
    return *this;
}

#endif // HAS_OPENCL
