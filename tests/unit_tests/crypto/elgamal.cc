/* Copyright (c) 2015-2018, The Kovri I2P Router Project                                      //
 * Copyright (c) 2019, oneiric
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <catch2/catch.hpp>

#include "src/crypto/rand.h"

#include "src/crypto/elgamal.h"

#include "tests/unit_tests/mock/crypto/elgamal.h"

namespace meta = ntcp2::meta::crypto::elgamal;

TEST_CASE_METHOD(
    MockElGamal,
    "ElGamal encrypts and decrypts a message",
    "[elgamal]")
{
  using Catch::Matchers::Equals;
  using vec = std::vector<std::uint8_t>;

  ntcp2::crypto::elgamal::Plaintext plaintext, result;

  ntcp2::crypto::RandBytes(plaintext.data(), plaintext.size());

  for (const auto& pad : zero_pad)
    {
      ntcp2::crypto::elgamal::Ciphertext ciphertext;

      REQUIRE_NOTHROW(enc.Encrypt(ciphertext, plaintext, pad));
      REQUIRE_NOTHROW(dec.Decrypt(result, ciphertext, pad));

      REQUIRE_THAT(
          vec(plaintext.begin(), plaintext.end()),
          Equals(vec(result.begin(), result.end())));
    }
}

TEST_CASE_METHOD(
    MockElGamal,
    "ElGamal rejects invalid plaintext checksum",
    "[elgamal]")
{
  ntcp2::crypto::elgamal::Plaintext plaintext;
  ntcp2::crypto::elgamal::Ciphertext ciphertext;

  REQUIRE_NOTHROW(enc.Encrypt(ciphertext, plaintext, zero_pad[false]));

  // invalidate the ciphertext to invalidate the decrypted checksum
  ntcp2::crypto::RandBytes(ciphertext.data(), ciphertext.size());

  REQUIRE_THROWS(dec.Decrypt(plaintext, ciphertext, zero_pad[false]));
}
