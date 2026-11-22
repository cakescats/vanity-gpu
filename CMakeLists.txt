cmake_minimum_required(VERSION 3.20)

# CUDA 12.4 does not accept gcc 15 as a host compiler; use g++-13 when present.
if(NOT DEFINED CMAKE_CUDA_HOST_COMPILER)
  find_program(GXX13 g++-13)
  if(GXX13)
    set(CMAKE_CUDA_HOST_COMPILER ${GXX13} CACHE FILEPATH "")
    set(CMAKE_CXX_COMPILER ${GXX13} CACHE FILEPATH "")
  endif()
endif()
if(NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
  set(CMAKE_CUDA_ARCHITECTURES 86)
endif()
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

project(vanity-gpu VERSION 1.0.0 LANGUAGES CXX CUDA)

# Version shown by --version; CI passes -DVG_VERSION=<git tag> for releases.
set(VG_VERSION "${PROJECT_VERSION}" CACHE STRING "version string shown by --version")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CUDA_STANDARD 17)

add_executable(vanity-gpu
  src/main.cpp
  src/rng.cpp
  src/hostcrypto.cpp
  src/pattern.cpp
  src/report.cpp
  src/cpu_secp.cpp
  src/engine_secp.cu
  src/engine_ed.cu)

target_include_directories(vanity-gpu PRIVATE src cuda)
target_compile_definitions(vanity-gpu PRIVATE VG_VERSION="${VG_VERSION}")
target_compile_options(vanity-gpu PRIVATE
  $<$<COMPILE_LANGUAGE:CXX>:-O2 -Wall>
  $<$<COMPILE_LANGUAGE:CUDA>:-O3 -lineinfo>)

# CPU workers (--cpu): vectorised Keccak for this machine's CPU (AVX-512 / AVX2)
option(VG_NATIVE_CPU "build the CPU workers with -march=native" ON)
if(VG_NATIVE_CPU)
  set_source_files_properties(src/cpu_secp.cpp PROPERTIES COMPILE_OPTIONS "-O3;-march=native;-Wno-psabi")
else()
  set_source_files_properties(src/cpu_secp.cpp PROPERTIES COMPILE_OPTIONS "-O3;-Wno-psabi")  # portable: generic SIMD
endif()

find_package(Threads REQUIRED)
target_link_libraries(vanity-gpu PRIVATE Threads::Threads)
