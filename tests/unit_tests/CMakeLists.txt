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

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(ntcp2-tests CXX)

add_executable(ntcp2-tests
  main.cc

  crypto/aes.cc
  crypto/elgamal.cc
  crypto/ed25519.cc

  ntcp2/bytes.cc
  ntcp2/meta.cc

  ntcp2/blocks/date_time.cc
  ntcp2/blocks/options.cc
  ntcp2/blocks/padding.cc
  ntcp2/blocks/router_info.cc

  ntcp2/router/address.cc
  ntcp2/router/certificate.cc
  ntcp2/router/identity.cc
  ntcp2/router/info.cc
  ntcp2/router/mapping.cc

  ntcp2/session_request/kdf.cc
  ntcp2/session_request/session_request.cc

  ntcp2/session_created/kdf.cc
  ntcp2/session_created/session_created.cc
  
  ntcp2/session_confirmed/session_confirmed.cc

  mock/handshake.h
  mock/crypto/elgamal.h)

target_include_directories(ntcp2-tests PRIVATE
  ${PROJECT_SOURCE_DIR}/deps/noise-c/lib
  ${PROJECT_SOURCE_DIR}/deps/noise-c/include)

target_link_libraries(ntcp2-tests PRIVATE ntcp2-core ntcp2-priv)

install(TARGETS ntcp2-tests RUNTIME DESTINATION ${CMAKE_CURRENT_BINARY_DIR}) 
