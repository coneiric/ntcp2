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

#include "src/ntcp2/session_request/session_request.h"
#include "src/ntcp2/session_created/session_created.h"
#include "src/ntcp2/session_confirmed/session_confirmed.h"

#include "tests/unit_tests/mock/crypto/elgamal.h"
#include "tests/unit_tests/mock/router/info.h"

/// @brief Container for performing a valid mock handshake
struct MockHandshake
{
  MockHandshake()
    : remote_info(CreateMockRouterInfo()),
      local_info(CreateMockRouterInfo()),
      sco_message(local_info)
  {
    const ntcp2::exception::Exception ex{"MockHandshake", __func__};

    ntcp2::noise::init_handshake<ntcp2::Initiator>(&initiator_state);
    ntcp2::noise::init_handshake<ntcp2::Responder>(&responder_state);

    InitializeSessionRequest();
  }

  /// @brief Initialize SessionRequest initiator + responder
  void InitializeSessionRequest()
  {
    const auto& ident_hash = remote_info->identity()->ident_hash();

    srq_initiator = std::make_unique<ntcp2::SessionRequest<ntcp2::Initiator>>(
        initiator_state, ident_hash, remote_info->iv());

    srq_responder = std::make_unique<ntcp2::SessionRequest<ntcp2::Responder>>(
        responder_state, ident_hash, remote_info->iv());
  }

  /// @brief Perform a valid SessionRequest between initiator + responder
  void ValidSessionRequest()
  {
    srq_responder->kdf().GenerateKeypair();
    srq_responder->kdf().DeriveKeys();
    srq_responder->kdf().get_local_static_public_key(remote_key);

    srq_initiator->kdf().DeriveKeys(remote_key);

    srq_message.options.update(sco_message.payload_size(), pad_len); 
    srq_initiator->ProcessMessage(srq_message);

    srq_responder->ProcessMessage(srq_message);
  }

  /// @brief After valid SessionRequest, initialize SessionCreated initiator + responder
  /// @detail Roles are switched according to Noise spec
  void InitializeSessionCreated()
  {
    scr_initiator = std::make_unique<ntcp2::SessionCreated<ntcp2::Initiator>>(
        responder_state, srq_message, router_hash, iv);

    scr_responder = std::make_unique<ntcp2::SessionCreated<ntcp2::Responder>>(
        initiator_state, srq_message, router_hash, iv);
  }

  /// @brief Perform a valid SessionCreated message exchange
  void ValidSessionCreated()
  {
    InitializeSessionCreated();

    scr_message.options.update(pad_len);
    scr_initiator->ProcessMessage(scr_message);
    scr_responder->ProcessMessage(scr_message);
  }

  /// @brief After valid SessionCreated, initialize SessionConfirmed initiator + responder
  /// @detail Roles are switched according to Noise spec
  void InitializeSessionConfirmed()
  {
    sco_initiator = std::make_unique<ntcp2::SessionConfirmed<ntcp2::Initiator>>(
        initiator_state, scr_message);

    sco_responder = std::make_unique<ntcp2::SessionConfirmed<ntcp2::Responder>>(
        responder_state, scr_message);
  }

  NoiseHandshakeState *initiator_state, *responder_state;

  ntcp2::crypto::pk::X25519 remote_key;
  ntcp2::router::IdentHash router_hash;
  ntcp2::crypto::aes::IV iv;
  std::shared_ptr<ntcp2::router::Info> remote_info, local_info;
  ntcp2::SessionRequestMessage srq_message;
  ntcp2::SessionCreatedMessage scr_message;
  ntcp2::SessionConfirmedMessage sco_message;

  const std::uint16_t m3p2_len{ntcp2::meta::session_request::MinMsg3Pt2Size};
  const std::uint16_t pad_len{17};  // arbitrary padding length

  std::unique_ptr<ntcp2::SessionRequest<ntcp2::Initiator>> srq_initiator; 
  std::unique_ptr<ntcp2::SessionRequest<ntcp2::Responder>> srq_responder; 

  std::unique_ptr<ntcp2::SessionCreated<ntcp2::Initiator>> scr_initiator; 
  std::unique_ptr<ntcp2::SessionCreated<ntcp2::Responder>> scr_responder; 

  std::unique_ptr<ntcp2::SessionConfirmed<ntcp2::Initiator>> sco_initiator; 
  std::unique_ptr<ntcp2::SessionConfirmed<ntcp2::Responder>> sco_responder; 
};
