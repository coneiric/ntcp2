/* Copyright (c) 2019, oneiric
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

#ifndef TESTS_UNIT_TESTS_MOCK_CRYPTO_ELGAMAL_H_
#define TESTS_UNIT_TESTS_MOCK_CRYPTO_ELGAMAL_H_

#include "src/crypto/elgamal.h"

inline ntcp2::crypto::elgamal::Keypair GenerateTestElGamalKeys()
{
  using ntcp2::meta::crypto::constants::elgg;
  using ntcp2::meta::crypto::constants::elgp;

  // Use random bytes as private key (unrealistic + DANGEROUS for real crypto!!!)
  //   Actual key generation takes a lot of time finding a suitable prime.
  //   See slow-tests for use of actual key generator.
  ntcp2::crypto::pk::ElGamal pk;
  ntcp2::crypto::sk::ElGamal sk;

  ntcp2::crypto::RandBytes(sk.data(), sk.size());

  a_exp_b_mod_c(elgg, CryptoPP::Integer(sk.data(), sk.size()), elgp)
      .Encode(pk.data(), pk.size());

  return {pk, sk};
}

struct MockElGamal
{
  MockElGamal() : keys(GenerateTestElGamalKeys()), enc(keys.pk), dec(keys.sk) {}

  const bool zero_pad[2] = {false, true};
  ntcp2::crypto::elgamal::Keypair keys;
  ntcp2::crypto::elgamal::Encryptor enc;
  ntcp2::crypto::elgamal::Decryptor dec;
};

#endif  // TESTS_UNIT_TESTS_MOCK_CRYPTO_ELGAMAL_H_
