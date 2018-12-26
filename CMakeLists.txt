# Copyright (c) 2019, oneiric
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# 
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# 
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Parts used from the Kovri I2p Router Project Copyright (c) 2013-2018

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(ntcp2-priv CXX)

option(BUILD_NOISE_C "Build NoiseC depedency" ON)
option(WITH_TESTS "Build NTCP2 test suite" OFF)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

add_library(ntcp2-priv INTERFACE)

# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7420 
set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Release>:NDEBUG>)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Require C++14 support (minimum version compilers guarantee this)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(NoiseC REQUIRED)
if (NOT TARGET NoiseC::NoiseC)
  include(BuildNoiseC)

  if (NOT TARGET NoiseC::NoiseC)
    message(FATAL_ERROR "Could not find NoiseC.")
  else()
    target_link_libraries(ntcp2-priv INTERFACE NoiseC::NoiseC)
  endif()
endif()

# From Kovri project, along with associated find and build scripts
find_package(CryptoPP REQUIRED)
if(NOT TARGET CryptoPP::CryptoPP)
  include(BuildCryptoPP)

  if(NOT TARGET CryptoPP::CryptoPP)
    message(FATAL_ERROR "Could not find Crypto++. See building instructions.")
  endif()
else()
  target_link_libraries(ntcp2-priv INTERFACE CryptoPP::CryptoPP)
  target_compile_definitions(ntcp2-priv INTERFACE WITH_CRYPTOPP)
endif()

find_package(Boost 1.66 REQUIRED COMPONENTS system)
if (NOT Boost_FOUND)
  message(FATAL_ERROR "Boost not found or requirement not satisfied.")
endif()

add_subdirectory(src)

if (WITH_TESTS)
  if(WITH_COVERAGE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 --coverage")
  endif()

  add_subdirectory(tests/unit_tests)

  if (WITH_SLOW_TESTS)
    add_subdirectory(tests/slow_tests)
  endif()
endif()
