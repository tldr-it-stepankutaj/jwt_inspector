#pragma once

#ifdef HAS_OPENCL

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#ifndef CL_TARGET_OPENCL_VERSION
#define CL_TARGET_OPENCL_VERSION 300
#endif
#include <CL/cl.h>
#endif

#include <stdexcept>
#include <string>

class CLBuffer;

class CLContext {
    cl_platform_id platform_ = nullptr;
    cl_device_id device_ = nullptr;
    cl_context context_ = nullptr;
    cl_command_queue queue_ = nullptr;

public:
    CLContext();
    ~CLContext();
    CLContext(const CLContext&) = delete;
    CLContext& operator=(const CLContext&) = delete;

    cl_program build_program(const std::string& source) const;
    std::string device_name() const;
    cl_context context() const { return context_; }
    cl_command_queue queue() const { return queue_; }
    cl_device_id device() const { return device_; }
};

class CLBuffer {
    cl_mem mem_ = nullptr;

public:
    CLBuffer() = default;
    CLBuffer(cl_context ctx, cl_mem_flags flags, size_t size, void* host_ptr = nullptr);
    ~CLBuffer();
    CLBuffer(CLBuffer&& other) noexcept;
    CLBuffer& operator=(CLBuffer&& other) noexcept;
    CLBuffer(const CLBuffer&) = delete;
    CLBuffer& operator=(const CLBuffer&) = delete;
    cl_mem get() const { return mem_; }
    operator cl_mem() const { return mem_; }
};

class CLKernel {
    cl_kernel kernel_ = nullptr;

public:
    CLKernel(cl_program program, const char* name);
    ~CLKernel();
    CLKernel(CLKernel&& other) noexcept;
    CLKernel& operator=(CLKernel&& other) noexcept;
    CLKernel(const CLKernel&) = delete;
    CLKernel& operator=(const CLKernel&) = delete;

    template<typename T>
    void set_arg(cl_uint index, const T& value) {
        cl_int err = clSetKernelArg(kernel_, index, sizeof(T), &value);
        if (err != CL_SUCCESS)
            throw std::runtime_error("Failed to set kernel arg " + std::to_string(index));
    }

    void set_arg(cl_uint index, const CLBuffer& buf);

    cl_kernel get() const { return kernel_; }
};

class CLProgram {
    cl_program program_ = nullptr;

public:
    CLProgram(const CLContext& ctx, const std::string& source);
    ~CLProgram();
    CLProgram(CLProgram&& other) noexcept;
    CLProgram& operator=(CLProgram&& other) noexcept;
    CLProgram(const CLProgram&) = delete;
    CLProgram& operator=(const CLProgram&) = delete;
    cl_program get() const { return program_; }
};

#endif // HAS_OPENCL
