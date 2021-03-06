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

#include <catch2/catch.hpp>

#include "src/crypto/rand.h"

#include "src/ntcp2/router/info.h"

#include "tests/unit_tests/mock/crypto/elgamal.h"

namespace meta = ntcp2::meta::router::info;

struct RouterInfoFixture
{
  RouterInfoFixture()
      : identity(new ntcp2::router::Identity(
            GenerateTestElGamalKeys(),
            ntcp2::crypto::ed25519::create_keys())),
        info(identity, addresses, options)
  {
  }

  std::shared_ptr<ntcp2::router::Identity> identity;
  std::vector<ntcp2::router::Address> addresses;
  ntcp2::router::Mapping options;
  ntcp2::router::Info info;
};

TEST_CASE_METHOD(RouterInfoFixture, "RouterInfo has valid router identity", "[ri]")
{
  namespace identity = ntcp2::meta::router::identity;

  REQUIRE(info.identity());
  REQUIRE(info.identity()->size() == identity::DefaultSize);
}

TEST_CASE_METHOD(RouterInfoFixture, "RouterInfo has valid date", "[ri]")
{
  REQUIRE(info.date());
}

TEST_CASE_METHOD(RouterInfoFixture, "RouterInfo has valid addresses", "[ri]")
{
  REQUIRE(info.addresses().size() == addresses.size());
}

TEST_CASE_METHOD(RouterInfoFixture, "RouterInfo has valid options", "[ri]")
{
  using Catch::Matchers::Equals;

  const auto noise_i = info.options().entry(std::string("i"));
  const auto iv = info.iv();

  REQUIRE_THAT(
      std::string(noise_i.begin(), noise_i.end()),
      Equals(ntcp2::crypto::Base64::Encode(iv.data(), iv.size())));
}

TEST_CASE_METHOD(RouterInfoFixture, "RouterInfo has valid signature", "[ri]")
{
  const auto& sig = info.signature();

  REQUIRE(sig.size() == info.identity()->signing()->sig_len());
  REQUIRE(info.identity()->signing()->Verify(
      info.buffer().data(), info.size() - sig.size(), sig));
}

TEST_CASE_METHOD(
    RouterInfoFixture,
    "RouterInfo has serializes and deserializes empty addresses + options",
    "[ri]")
{
  REQUIRE_NOTHROW(info.serialize());
  REQUIRE_NOTHROW(info.deserialize());
}

TEST_CASE_METHOD(
    RouterInfoFixture,
    "RouterInfo has serializes and deserializes non-empty addresses + options",
    "[ri]")
{
  info.addresses().emplace_back(ntcp2::router::Address());
  info.options().add(std::string("host"), std::string("127.0.0.1"));

  REQUIRE_NOTHROW(info.serialize());
  REQUIRE_NOTHROW(info.deserialize());
}

TEST_CASE_METHOD(
    RouterInfoFixture,
    "RouterInfo can sign a message with its router identity",
    "[ri]")
{
  ntcp2::crypto::ed25519::Signature sig;

  std::array<std::uint8_t, 19> msg;
  ntcp2::crypto::RandBytes(msg.data(), msg.size());

  REQUIRE_NOTHROW(info.identity()->signing()->Sign(msg.data(), msg.size(), sig));
}
