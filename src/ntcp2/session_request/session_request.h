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

#ifndef SRC_SESSION_REQUEST_SESSION_REQUEST_H_
#define SRC_SESSION_REQUEST_SESSION_REQUEST_H_

#include <chrono>

#include <noise/protocol/handshakestate.h>

#include "src/crypto/aes.h"
#include "src/crypto/rand.h"

#include "src/ntcp2/router/info.h"

#include "src/ntcp2/session_request/kdf.h"
#include "src/ntcp2/session_request/meta.h"
#include "src/ntcp2/session_request/options.h"

namespace ntcp2
{
struct SessionRequestMessage
{
  std::vector<std::uint8_t> data, padding;
  std::array<std::uint8_t, ntcp2::meta::session_request::CiphertextSize>
      ciphertext;
  ntcp2::session_request::Options options;
};

template <class Role_t>
class SessionRequest
{
  Role_t role_;
  NoiseHandshakeState* state_;
  ntcp2::SessionRequestKDF<Role_t> kdf_;
  ntcp2::crypto::pk::X25519 x_;
  ntcp2::crypto::aes::CBCEncryption encryption_;
  ntcp2::crypto::aes::CBCDecryption decryption_;

 public:
  SessionRequest(
      NoiseHandshakeState* state,
      const ntcp2::router::IdentHash& router_hash,
      const ntcp2::crypto::aes::IV& iv)
      : state_(state),
        kdf_(state_),
        encryption_(router_hash, iv),
        decryption_(router_hash, iv)
  {
  }

  /// @brief Get a mutable reference to the KDF object
  decltype(kdf_)& kdf() noexcept
  {
    return kdf_;
  }

  /// @brief Get a const reference to the KDF object
  const decltype(kdf_)& kdf() const noexcept
  {
    return kdf_;
  }

  /// @brief Get a const reference to the encrypted X value
  /// @detail Useful for session management
  const decltype(x_)& x() const noexcept
  {
    return x_;
  }

  /// @brief Process session request message based on role
  void ProcessMessage(SessionRequestMessage& message)
  {
    if (role_.id() == NOISE_ROLE_INITIATOR)
      Write(message);  // write and encrypt message
    else
      Read(message);  // decrypt and read message
  }

 private:
  void Write(SessionRequestMessage& message)
  {
    namespace pk = ntcp2::crypto::pk;

    using ntcp2::meta::session_request::NoisePayloadSize;

    const exception::Exception ex{"SessionRequest", __func__};

    NoiseBuffer data /*output*/, payload /*input*/;

    // ensure enough room to hold Noise payload + padding
    message.data.resize(NoisePayloadSize + message.options.pad_len);

    auto& in = message.options.buf;
    auto& out = message.data;

    ntcp2::noise::RawBuffers bufs{in.data(), in.size(), out.data(), out.size()};
    ntcp2::noise::setup_buffers(data, payload, bufs);
    ntcp2::noise::write_message(state_, &data, &payload, ex);

    // encrypt ephemeral key in place
    encryption_.Process(out.data(), pk::X25519Len, out.data(), pk::X25519Len);

    // save encrypted X for session managment
    save_x(message);

    // save ciphertext for session created KDF
    save_ciphertext(message);

    if (message.options.pad_len)
      process_padding(message);  // add out-of-frame NTCP2 padding
  }

  void Read(SessionRequestMessage& message)
  {
    namespace meta = ntcp2::meta::session_request;
    namespace pk = ntcp2::crypto::pk;

    const ntcp2::exception::Exception ex{"SessionRequest", __func__};

    NoiseBuffer data /*input*/, payload /*output*/;

    auto& in = message.data;
    auto& out = message.options.buf;
    const auto& in_size = meta::NoisePayloadSize;

    if (in.size() < meta::MinSize || in.size() > meta::MaxSize)
      ex.throw_ex<std::length_error>("invalid message size.");

    // save encrypted X for session managment
    save_x(message);

    // save ciphertext for session created KDF
    save_ciphertext(message);

    // decrypt ephemeral key in place
    decryption_.Process(in.data(), pk::X25519Len, in.data(), pk::X25519Len);

    ntcp2::noise::RawBuffers bufs{in.data(), in_size, out.data(), out.size()};
    ntcp2::noise::setup_buffers(payload, data, bufs);
    ntcp2::noise::read_message(state_, &data, &payload, ex);

    // deserialize options from buffer
    message.options.deserialize();

    if (message.options.pad_len)
      process_padding(message);  // save padding for session created KDF
  }

  void process_padding(SessionRequestMessage& message)
  {
    using ntcp2::meta::session_request::PaddingOffset;

    auto& p = message.padding;

    p.clear();
    p.resize(message.options.pad_len);

    if (role_.id() == NOISE_ROLE_INITIATOR)
      {  // write random padding to message
        ntcp2::crypto::RandBytes(p.data(), p.size());
        std::copy(p.begin(), p.end(), &message.data[PaddingOffset]);
      }
    else
      {  // read random padding from message
        const auto* beg = &message.data[PaddingOffset];
        std::copy(beg, beg + p.size(), p.data());
      }
  }

  void save_x(const SessionRequestMessage& message)
  {
    namespace pk = ntcp2::crypto::pk;

    const auto beg = message.data.begin();
    std::copy(beg, beg + pk::X25519Len, x_.begin());
  }

  void save_ciphertext(SessionRequestMessage& message)
  {
    namespace meta = ntcp2::meta::session_request;

    const auto c = &message.data[meta::CiphertextOffset];
    std::copy(c, c + meta::CiphertextSize, message.ciphertext.data());
  }
};
}  // namespace ntcp2
#endif  // SRC_SESSION_REQUEST_SESSION_REQUEST_H_
