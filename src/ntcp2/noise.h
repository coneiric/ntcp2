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

#ifndef SRC_NTCP2_NOISE_H_
#define SRC_NTCP2_NOISE_H_

#include <noise/protocol/handshakestate.h>

#include "src/exception/exception.h"
#include "src/crypto/meta.h"
#include "src/ntcp2/meta.h"

// Simple wrappers for NoiseC functions

namespace ntcp2
{
namespace noise
{
/// @brief Container for raw Noise buffers
struct RawBuffers
{
  std::uint8_t *in_buf;
  const std::size_t in_size;

  std::uint8_t *out_buf;
  const std::size_t out_size;
};

/// @brief Initialize Noise handshake state
/// @param state Noise handshakestate to initialize
/// @throw Runtime error if Noise library returns an error
template <class Role_t>
inline void init_handshake(NoiseHandshakeState** state)
{
  const ntcp2::exception::Exception ex{"NTCP2: Noise", __func__};

  const int err = noise_handshakestate_new_by_name(
      state, ntcp2::meta::name(), Role_t().id());

  if (err)
    ex.throw_ex<std::runtime_error>("error initializing handshake state", err);
}

/// @brief Initialize Noise message buffers
/// @param out Output buffer to setup
/// @param in Input buffer to setup
/// @param buffers Container for raw buffers
inline void setup_buffers(NoiseBuffer& out, NoiseBuffer& in, RawBuffers& buffers)
{
  noise_buffer_set_input(in, buffers.in_buf, buffers.in_size);
  noise_buffer_set_output(out, buffers.out_buf, buffers.out_size);
}

/// @brief Write Noise message to buffer
/// @param state Noise handshakestate to initialize
/// @param data Write message to this Noise buffer
/// @param payload Write this payload buffer to the message buffer
/// @param ex Exception handler
/// @throw Runtime error if Noise returns an error
inline void write_message(
    NoiseHandshakeState* state,
    NoiseBuffer* data,
    NoiseBuffer* payload,
    const ntcp2::exception::Exception& ex)
{
  const int err = noise_handshakestate_write_message(state, data, payload);
  if (err)
      ex.throw_ex<std::runtime_error>("unable to write message", err);
}

/// @brief Read Noise message from buffer
/// @param state Noise handshakestate to initialize
/// @param data Read message from this Noise buffer
/// @param payload Read from the message buffer into this payload buffer
/// @param ex Exception handler
/// @throw Runtime error if Noise returns an error
inline void read_message(
    NoiseHandshakeState* state,
    NoiseBuffer* data,
    NoiseBuffer* payload,
    const ntcp2::exception::Exception& ex)
{
  const int err = noise_handshakestate_read_message(state, data, payload);
  if (err)
      ex.throw_ex<std::runtime_error>("unable to read message", err);
}

/// @brief Get Noise local static public key
/// @param state Handshake state containing the key
/// @param key Key to populate with the public key
/// @throw Runtime error if Noise library returns error
inline void get_local_static_public_key(
    const NoiseHandshakeState* state,
    ntcp2::crypto::pk::X25519& key)
{
  const ntcp2::exception::Exception ex{"NTCP2: Noise", __func__};

  auto* dh = noise_handshakestate_get_local_keypair_dh(state);

  if (!dh)
    ex.throw_ex<std::runtime_error>("unable to get local keypair.");

  const int err = noise_dhstate_get_public_key(dh, key.data(), key.size());

  if (err)
    ex.throw_ex<std::runtime_error>("unable to get public key.");
}

/// @brief Get the final Noise handshake hash
/// @param state Noise handshake state containing the hash
/// @param hash Hash to populate with the Noise hash
/// @throw Runtime error if Noise library returns error
inline void get_handshake_hash(
    const NoiseHandshakeState* state,
    ntcp2::crypto::hash::Sha256& hash)
{
  const ntcp2::exception::Exception ex{"NTCP2: Noise", __func__};

  const int err =
      noise_handshakestate_get_handshake_hash(state, hash.data(), hash.size());

  if (err)
    ex.throw_ex<std::runtime_error>("unable to get handshake hash", err);
}

/// @brief Set the remote public key
/// @param state Noise handshake state containing the remote key 
/// @param key Remote key to set
/// @throw Runtime error if Noise library returns error
inline void set_remote_public_key(
    NoiseHandshakeState* state,
    const ntcp2::crypto::pk::X25519& key)
{
  const ntcp2::exception::Exception ex{"NTCP2: Noise", __func__};

  auto* dh = noise_handshakestate_get_remote_public_key_dh(state);

  if (!dh)
    ex.throw_ex<std::runtime_error>("unable to get remote public key");

  const int err = noise_dhstate_set_public_key(dh, key.data(), key.size());

  if (err)
    ex.throw_ex<std::runtime_error>("unable to set remote public key", err);
}

/// @brief Perform Noise MixHash on given buffer
/// @param state Noise handshake state pointer
/// @param buf Buffer data to supply to MixHash
/// @param ex Exception handler
template <class Buffer>
inline void mix_hash(
    NoiseHandshakeState* state,
    Buffer& buf,
    const ntcp2::exception::Exception& ex)
{
  if (const int err =
          noise_handshakestate_mix_hash(state, buf.data(), buf.size()))
    ex.throw_ex<std::runtime_error>("error performing MixHash", err);
}
}  // namespace noise
}  // namespace ntcp2

#endif  // SRC_NTCP2_NOISE_H_
