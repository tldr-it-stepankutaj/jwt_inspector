cmake_minimum_required(VERSION 3.10)
project(jwt_opencl_bruteforce)

set(CMAKE_CXX_STANDARD 17)

set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
find_package(OpenSSL REQUIRED)

# OpenCL (Apple)
find_package(OpenCL REQUIRED)

include_directories(
        ${OpenSSL_INCLUDE_DIR}
        ${OpenCL_INCLUDE_DIRS}
        include
        /opt/homebrew/include
)

link_directories(
        ${OPENSSL_LIBRARIES}
        ${OpenCL_LIBRARY}
)

add_executable(jwt_inspector
        src/main.cpp
        src/jwt_bruteforce.cpp
)

target_link_libraries(jwt_inspector
        OpenSSL::Crypto
        ${OpenCL_LIBRARIES}
)