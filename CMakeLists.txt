cmake_minimum_required(VERSION 3.16)
project(AuthForgeCPPSDK VERSION 1.0.2 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(AUTHFORGE_BUILD_VECTOR_GENERATOR "Build the test vector generator" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

find_path(SODIUM_INCLUDE_DIR sodium.h REQUIRED)
find_library(SODIUM_LIBRARY NAMES sodium libsodium REQUIRED)

add_library(authforge_sdk authforge_sdk.cpp)
target_include_directories(authforge_sdk PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<INSTALL_INTERFACE:include>
)
target_include_directories(authforge_sdk PRIVATE ${SODIUM_INCLUDE_DIR})
target_link_libraries(authforge_sdk PUBLIC OpenSSL::Crypto CURL::libcurl Threads::Threads)
target_link_libraries(authforge_sdk PRIVATE ${SODIUM_LIBRARY})

if(WIN32)
  target_link_libraries(authforge_sdk PRIVATE iphlpapi ws2_32)
endif()

install(
  TARGETS authforge_sdk
  EXPORT authforgeTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES authforge_sdk.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(
  EXPORT authforgeTargets
  FILE AuthForgeTargets.cmake
  NAMESPACE AuthForge::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AuthForge
)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/AuthForgeConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/AuthForgeConfig.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/AuthForge"
)

install(
  FILES "${CMAKE_CURRENT_BINARY_DIR}/AuthForgeConfig.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AuthForge
)

if(AUTHFORGE_BUILD_VECTOR_GENERATOR)
  add_executable(generate_vectors generate_vectors.cpp)
  target_link_libraries(generate_vectors PRIVATE OpenSSL::Crypto)
endif()
