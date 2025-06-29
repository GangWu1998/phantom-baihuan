cmake_minimum_required(VERSION 3.20)

project(Phantom LANGUAGES CXX CUDA VERSION 2.1 DESCRIPTION "CUDA-Accelerated Homomorphic Encryption Library")

# [option] PHANTOM_USE_CUDA_PTX (default: ON)
option(PHANTOM_USE_CUDA_PTX "Use CUDA PTX Assembly" ON)
message(STATUS "Use CUDA PTX Assembly: ${PHANTOM_USE_CUDA_PTX}")
if (PHANTOM_USE_CUDA_PTX)
    add_compile_definitions(PHANTOM_USE_CUDA_PTX)
endif ()

if (NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
    set(CMAKE_CUDA_ARCHITECTURES native)
endif ()

# use C++20
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

# CUDA separable compilation
set(CMAKE_CUDA_SEPARABLE_COMPILATION ON)

# -fPIC
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)

# library
add_subdirectory(src)

# find NTL and GMP library
find_library(NTL_LIBRARY NAMES ntl NTL)
set(GMP_LIBRARY /usr/local/lib/libgmp.a CACHE FILEPATH "Path to static GMP library")
#find_library(GMP_LIBRARY NAMES gmp)

# find head files path
find_path(NTL_INCLUDE_DIR NAMES NTL/ZZ.h)
find_path(GMP_INCLUDE_DIR NAMES gmp.h)

# message
message(STATUS "NTL_LIBRARY = ${NTL_LIBRARY}")
message(STATUS "NTL_INCLUDE_DIR = ${NTL_INCLUDE_DIR}")
message(STATUS "GMP_LIBRARY = ${GMP_LIBRARY}")
message(STATUS "GMP_INCLUDE_DIR = ${GMP_INCLUDE_DIR}")

# include directories
include_directories(${NTL_INCLUDE_DIR} ${GMP_INCLUDE_DIR})

# example
# [option] PHANTOM_ENABLE_EXAMPLE (default: ON)
option(PHANTOM_ENABLE_EXAMPLE "Enable examples" ON)
message(STATUS "Enable examples: ${PHANTOM_ENABLE_EXAMPLE}")
if (PHANTOM_ENABLE_EXAMPLE)
    add_subdirectory(examples)
endif ()

# benchmark
# [option] PHANTOM_ENABLE_BENCH (default: OFF)
option(PHANTOM_ENABLE_BENCH "Enable benchmarks" OFF)
message(STATUS "Enable benchmarks: ${PHANTOM_ENABLE_BENCH}")
if (PHANTOM_ENABLE_BENCH)
    add_subdirectory(benchmark)
endif ()

# test
# [option] PHANTOM_ENABLE_TEST (default: OFF)
option(PHANTOM_ENABLE_TEST "Enable tests" OFF)
message(STATUS "Enable tests: ${PHANTOM_ENABLE_TEST}")
if (PHANTOM_ENABLE_TEST)
    add_subdirectory(test)
endif ()

# python binding
# [option] PHANTOM_ENABLE_PYTHON_BINDING (default: OFF)
option(PHANTOM_ENABLE_PYTHON_BINDING "Enable python binding" OFF)
message(STATUS "Enable python binding: ${PHANTOM_ENABLE_PYTHON_BINDING}")
if (PHANTOM_ENABLE_PYTHON_BINDING)
    add_subdirectory(python)
endif ()

# config for installation
install(TARGETS Phantom EXPORT PhantomConfig)
install(EXPORT PhantomConfig NAMESPACE phantom:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/phantom)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/phantom)
