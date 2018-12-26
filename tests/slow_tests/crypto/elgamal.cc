/* Copyright (c) 2019, oneiric
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

struct ElGamalFixture
{
  ElGamalFixture()
  {  // create keys using the slow, real-use generator
    keys = ntcp2::crypto::elgamal::create_keys();

    enc = std::make_unique<ntcp2::crypto::elgamal::Encryptor>(keys.pk);
    dec = std::make_unique<ntcp2::crypto::elgamal::Decryptor>(keys.sk);
  }

  ntcp2::crypto::elgamal::Keypair keys;
  const bool zero_pad[2] = {false, true};
  std::unique_ptr<ntcp2::crypto::elgamal::Encryptor> enc;
  std::unique_ptr<ntcp2::crypto::elgamal::Decryptor> dec;
};

TEST_CASE_METHOD(ElGamalFixture, "ElGamal encrypts and decrypts a message", "[elgamal]")
{
  namespace meta = ntcp2::meta::crypto::elgamal;

  using Catch::Matchers::Equals;
  using vec = std::vector<std::uint8_t>;

  ntcp2::crypto::elgamal::Plaintext plaintext, result;

  ntcp2::crypto::RandBytes(plaintext.data(), plaintext.size());

  for (const auto& pad : zero_pad)
    {
      ntcp2::crypto::elgamal::Ciphertext ciphertext;

      REQUIRE_NOTHROW(enc->Encrypt(ciphertext, plaintext, pad));
      REQUIRE_NOTHROW(dec->Decrypt(result, ciphertext, pad));

      REQUIRE_THAT(
          vec(plaintext.begin(), plaintext.end()),
          Equals(vec(result.begin(), result.end())));
    }
}
