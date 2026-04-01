cmake_minimum_required(VERSION 3.10)
project(jwt_inspector LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------- Dependencies ----------

find_package(OpenSSL REQUIRED)

# nlohmann/json — try system package first, then FetchContent
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG        v3.11.3
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# OpenCL — optional
option(ENABLE_OPENCL "Build with OpenCL GPU support" ON)
if(ENABLE_OPENCL)
    find_package(OpenCL QUIET)
    if(OpenCL_FOUND)
        message(STATUS "OpenCL found: ${OpenCL_LIBRARIES}")
    else()
        message(STATUS "OpenCL not found — GPU bruteforce will be disabled")
    endif()
endif()

# ---------- Sources ----------

set(JWT_SOURCES
    src/main.cpp
    src/cli.cpp
    src/jwt_utils.cpp
    src/jwt_decoder.cpp
    src/jwt_bruteforce_cpu.cpp
    src/jwt_bruteforce_gpu.cpp
    src/jwt_verifier.cpp
    src/generative_bruteforce.cpp
    src/progress.cpp
    src/opencl_context.cpp
)

add_executable(jwt_inspector ${JWT_SOURCES})

target_include_directories(jwt_inspector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(jwt_inspector PRIVATE
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

if(ENABLE_OPENCL AND OpenCL_FOUND)
    target_compile_definitions(jwt_inspector PRIVATE HAS_OPENCL)
    target_include_directories(jwt_inspector PRIVATE ${OpenCL_INCLUDE_DIRS})
    target_link_libraries(jwt_inspector PRIVATE ${OpenCL_LIBRARIES})
endif()

# ---------- Tests ----------

option(BUILD_TESTS "Build unit tests" OFF)
if(BUILD_TESTS)
    enable_testing()

    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
        GIT_SHALLOW    TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    # Test sources (share all non-main sources)
    set(JWT_LIB_SOURCES
        src/cli.cpp
        src/jwt_utils.cpp
        src/jwt_decoder.cpp
        src/jwt_bruteforce_cpu.cpp
        src/jwt_bruteforce_gpu.cpp
        src/jwt_verifier.cpp
        src/generative_bruteforce.cpp
        src/progress.cpp
        src/opencl_context.cpp
    )

    add_library(jwt_lib STATIC ${JWT_LIB_SOURCES})
    target_include_directories(jwt_lib PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(jwt_lib PUBLIC
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
    )
    if(ENABLE_OPENCL AND OpenCL_FOUND)
        target_compile_definitions(jwt_lib PUBLIC HAS_OPENCL)
        target_include_directories(jwt_lib PUBLIC ${OpenCL_INCLUDE_DIRS})
        target_link_libraries(jwt_lib PUBLIC ${OpenCL_LIBRARIES})
    endif()

    add_executable(jwt_tests
        tests/test_jwt_utils.cpp
        tests/test_jwt_decoder.cpp
        tests/test_bruteforce_cpu.cpp
        tests/test_jwt_verifier.cpp
        tests/test_generative.cpp
    )
    target_link_libraries(jwt_tests PRIVATE jwt_lib GTest::gtest_main)
    include(GoogleTest)
    gtest_discover_tests(jwt_tests)
endif()

# ---------- Install ----------

install(TARGETS jwt_inspector RUNTIME DESTINATION bin)
install(DIRECTORY kernels/ DESTINATION share/jwt_inspector/kernels)
