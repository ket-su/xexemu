cmake_minimum_required(VERSION 3.20)
project(xexemu VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")

include_directories(include)

add_executable(xexemu
    src/main.cpp
    src/xex2_parser.cpp
    src/xex2_loader.cpp
    src/xex2_validator.cpp
)

target_include_directories(xexemu PRIVATE include)