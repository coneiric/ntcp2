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

#include "src/ntcp2/noise.h"
#include "src/ntcp2/session_created/kdf.h"

#include "tests/unit_tests/mock/handshake.h"

struct SessionCreatedConfirmedKDFFixture : public MockHandshake
{
  SessionCreatedConfirmedKDFFixture()
  {
    ValidSessionRequest();

    // switch roles from SessionRequest
    initiator_kdf =
        std::make_unique<ntcp2::SessionCreatedConfirmedKDF<ntcp2::Initiator>>(
            responder_state);

    responder_kdf =
        std::make_unique<ntcp2::SessionCreatedConfirmedKDF<ntcp2::Responder>>(
            initiator_state);
  }

  std::unique_ptr<ntcp2::SessionCreatedConfirmedKDF<ntcp2::Initiator>> initiator_kdf;
  std::unique_ptr<ntcp2::SessionCreatedConfirmedKDF<ntcp2::Responder>> responder_kdf;
};

TEST_CASE_METHOD(
    SessionCreatedConfirmedKDFFixture,
    "Session created initiator derives keys",
    "[scr_kdf]")
{
  // derive keys with SessionRequest ciphertext + padding
  REQUIRE_NOTHROW(initiator_kdf->DeriveKeys(srq_message));
}

TEST_CASE_METHOD(
    SessionCreatedConfirmedKDFFixture,
    "Session created responder derives keys",
    "[scr_kdf]")
{
  // derive keys with SessionRequest ciphertext + padding
  REQUIRE_NOTHROW(responder_kdf->DeriveKeys(srq_message));
}
