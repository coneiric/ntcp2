# copyright (c) 2018, oneiric
# all rights reserved.
# 
# redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# * redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# 
# * redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# 
# * neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
# 
# this software is provided by the copyright holders and contributors "as is"
# and any express or implied warranties, including, but not limited to, the
# implied warranties of merchantability and fitness for a particular purpose are
# disclaimed. in no event shall the copyright holder or contributors be liable
# for any direct, indirect, incidental, special, exemplary, or consequential
# damages (including, but not limited to, procurement of substitute goods or
# services; loss of use, data, or profits; or business interruption) however
# caused and on any theory of liability, whether in contract, strict liability,
# or tort (including negligence or otherwise) arising in any way out of the use
# of this software, even if advised of the possibility of such damage.
#
# Parts used from The Kovri I2P Router Project Copyright (c) 2013-2018

set(NOISEC_ROOT "${PROJECT_SOURCE_DIR}/deps/noise-c/build")

find_path(NoiseC_INCLUDE_DIR
  NAME protocol.h
  PATHS ${NOISEC_ROOT}/include
  PATH_SUFFIXES noise
  NO_DEFAULT_PATH)

find_path(NoiseC_LIBRARIES
  NAME libnoiseprotocol
  PATHS ${NOISEC_ROOT}/lib
  NO_DEFAULT_PATH)

if (EXISTS "${NoiseC_INCLUDE_DIR}" AND EXISTS "${NoiseC_LIBRARIES}" AND NOT TARGET NoiseC::NoiseC)
  add_library(NoiseC::NoiseC STATIC IMPORTED)

  set_target_properties(NoiseC::NoiseC PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${NoiseC_INCLUDE_DIR};${NoiseC_INCLUDE_DIR}/..")

  set_target_properties(NoiseC::NoiseC PROPERTIES
    IMPORTED_LINK_INTERFACE_LANGUAGES "C"
    IMPORTED_LOCATION "${NoiseC_LIBRARIES}")
endif()
