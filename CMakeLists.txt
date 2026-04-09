cmake_minimum_required(VERSION 3.16)
project(AuthForgeCPPSDK LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

add_library(authforge_sdk authforge_sdk.cpp)
target_include_directories(authforge_sdk PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(authforge_sdk PUBLIC OpenSSL::Crypto CURL::libcurl Threads::Threads)

if(WIN32)
  target_link_libraries(authforge_sdk PRIVATE iphlpapi ws2_32)
endif()

add_executable(generate_vectors generate_vectors.cpp)
target_link_libraries(generate_vectors PRIVATE OpenSSL::Crypto)
