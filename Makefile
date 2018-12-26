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
# Parts used from The Kovri I2P Router Project Copyright (c) 2013-2018

SHELL := $(shell which bash)

cmake_target = all

cmake-ntcp2  =

ntcp2-debug      = cmake -D CMAKE_BUILD_TYPE=Debug
ntcp2-noisec     = -D BUILD_NOISE_C=ON
ntcp2-coverage   = -D WITH_COVERAGE=ON
ntcp2-cryptopp   = -D BUILD_CRYPTOPP=ON
ntcp2-tests      = -D WITH_TESTS=ON
ntcp2-slow-tests = -D WITH_SLOW_TESTS=ON

noise-c = deps/noise-c
cryptopp = deps/cryptopp

build = build/

# cmake builder macro (courtesy of Kovri project)
define CMAKE
  cmake -E make_directory $1
	cmake -E chdir $1 $2 ../
endef

define PREP_NOISE_C
  cd $(noise-c); \
	autoreconf -i;
endef

define CLEAN_NOISE_C
  cd $(noise-c); \
  rm -rf build/*; \
	make clean;
endef

define CLEAN_CRYPTOPP
  cd $(cryptopp); \
	make clean;
endef

deps:
	$(eval cmake-ntcp2 += $(ntcp2-noisec) $(ntcp2-cryptopp)
	$(call PREP_NOISE_C)

all: deps

tests: all
	$(eval cmake-ntcp2 += $(ntcp2-debug) $(ntcp2-tests))
	$(call CMAKE,$(build),$(cmake-ntcp2)) && ${MAKE} -C $(build) $(cmake_target)

slow-tests: all
	$(eval cmake-ntcp2 += $(ntcp2-debug) $(ntcp2-tests) $(ntcp2-slow-tests))
	$(call CMAKE,$(build),$(cmake-ntcp2)) && ${MAKE} -C $(build) $(cmake_target)

coverage: all
	$(eval cmake-ntcp2 += $(ntcp2-debug) $(ntcp2-coverage) $(ntcp2-tests))
	$(call CMAKE,$(build),$(cmake-ntcp2)) && ${MAKE} -C $(build) $(cmake_target)

clean:
	rm -rf $(build)

clean-deps:
	$(call CLEAN_NOISE_C)
	$(call CLEAN_CRYPTOPP)

.PHONY: all tests slow-tests clean
