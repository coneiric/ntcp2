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

#ifndef SRC_NTCP2_SESSION_CONFIRMED_SESSION_CONFIRMED_H_
#define SRC_NTCP2_SESSION_CONFIRMED_SESSION_CONFIRMED_H_

#include <noise/protocol/handshakestate.h>

#include "src/ntcp2/session_request/options.h"

#include "src/ntcp2/session_created/kdf.h"

#include "src/ntcp2/blocks/options.h"
#include "src/ntcp2/blocks/padding.h"
#include "src/ntcp2/blocks/router_info.h"

#include "src/ntcp2/session_confirmed/meta.h"

namespace ntcp2
{
/// @brief Container for session created message
struct SessionConfirmedMessage
{
  CryptoPP::SecByteBlock data;
  CryptoPP::SecByteBlock payload;
  ntcp2::RouterInfoBlock ri_block;
  ntcp2::OptionsBlock opt_block;
  ntcp2::PaddingBlock pad_block;

  explicit SessionConfirmedMessage(
      const std::shared_ptr<ntcp2::router::Info> info)
      : ri_block(info)
  {
  }

  /// @brief Get the total SessionConfirmed message size
  boost::endian::big_uint16_t size() const
  {
    return meta::session_confirmed::PartOneSize + payload_size()
           + (2 * crypto::hash::Poly1305Len);
  }

  /// @brief Get the SessionConfirmed part two payload size
  boost::endian::big_uint16_t payload_size() const
  { 
    const auto& opt_size = opt_block.data_size();
    const auto& pad_size = pad_block.data_size();

    return ri_block.size() + (opt_size ? opt_block.size() : opt_size)
           + (pad_size ? pad_block.size() : pad_size);
  }
};

/// @brief Session created message handler
template <class Role_t>
class SessionConfirmed
{
  Role_t role_;
  NoiseHandshakeState* state_;
  SessionCreatedConfirmedKDF<Role_t> kdf_;

 public:
  /// @brief Initialize a session created message handler
  /// @param state Handshake state from successful session requested exchange
  /// @param message SessionCreated message with ciphertext + padding for KDF
  SessionConfirmed(
      NoiseHandshakeState* state,
      const ntcp2::SessionCreatedMessage& message)
      : state_(state), kdf_(state)
  {
    kdf_.DeriveKeys(message);
  }

  /// @brief Process the session created message based on role
  /// @param message Session created message to process
  /// @throw Runtime error if Noise library returns error
  void ProcessMessage(
      SessionConfirmedMessage& message,
      const session_request::Options& options)
  {
    if (role_.id() == NOISE_ROLE_INITIATOR)
      Write(message, options);
    else
      Read(message, options);
  }

 private:
  void Write(
      SessionConfirmedMessage& message,
      const session_request::Options& options)
  {
    namespace pk = ntcp2::crypto::pk;

    const exception::Exception ex{"SessionConfirmed", __func__};

    NoiseBuffer data /*output*/, payload /*input*/;

    if (options.m3p2_len != message.payload_size())
      ex.throw_ex<std::logic_error>(
          "part two size must equal to size sent in SessionRequest");

    // resize the buffers for part one & two messages
    message.data.resize(message.size());
    message.payload.resize(message.payload_size());

    ntcp2::BytesWriter<decltype(message.payload)> writer(message.payload);

    // serialize and write RouterInfo block to payload buffer
    message.ri_block.serialize();
    writer.write_data(message.ri_block.buffer());

    if (message.opt_block.data_size())
      {  // serialize and write Options block to payload buffer
        message.opt_block.serialize();
        writer.write_data(message.opt_block.buffer());
      }

    if (message.pad_block.data_size())
      {  // serialize and write Padding block to payload buffer
        message.pad_block.serialize();
        writer.write_data(message.pad_block.buffer());
      }

    auto& in = message.payload;
    auto& out = message.data;

    ntcp2::noise::RawBuffers bufs{in.data(), in.size(), out.data(), out.size()};
    ntcp2::noise::setup_buffers(data, payload, bufs);
    ntcp2::noise::write_message(state_, &data, &payload, ex);
  }

  void Read(
      SessionConfirmedMessage& message,
      const session_request::Options& options)
  {
    namespace meta = ntcp2::meta::session_confirmed;
    namespace block = ntcp2::meta::block;
    namespace pk = ntcp2::crypto::pk;

    const exception::Exception ex{"SessionConfirmed", __func__};

    NoiseBuffer data /*input*/, payload /*output*/;

    message.payload.resize(options.m3p2_len);

    auto& in = message.data;
    auto& out = message.payload;
    const std::uint16_t in_size =
        meta::PartOneSize + options.m3p2_len + crypto::hash::Poly1305Len;

    if (in.size() < meta::MinSize || in.size() > meta::MaxSize)
      ex.throw_ex<std::length_error>("invalid message size.");

    ntcp2::noise::RawBuffers bufs{in.data(), in_size, out.data(), out.size()};
    ntcp2::noise::setup_buffers(payload, data, bufs);
    ntcp2::noise::read_message(state_, &data, &payload, ex);

    process_payload(message, options, ex);
  }

 private:
  void process_payload(
      SessionConfirmedMessage& message,
      const session_request::Options& options,
      const exception::Exception& ex)
  {
    namespace block = ntcp2::meta::block;

    ntcp2::BytesReader<decltype(message.payload)> reader(message.payload);

    const auto read_deserialize = [&reader, message](Block& out_block) {
      // read block size
      boost::endian::big_uint16_t block_size;
      ntcp2::read_bytes(
          &message.payload[reader.count() + block::SizeOffset], block_size);

      // read and deserialize the block
      if (block_size)
        {
          out_block.buffer().resize(block::HeaderSize + block_size);
          reader.read_data(out_block.buffer());
          out_block.deserialize();
        }
      else
        reader.skip_bytes(block::HeaderSize);
    };

    if (reader.gcount() >= block::HeaderSize)
      {
        std::uint8_t block_type;
        ntcp2::read_bytes(&message.payload[reader.count()], block_type);

        if (block_type == block::RouterInfoID)
          read_deserialize(message.ri_block);
        else
          ex.throw_ex<std::logic_error>("RouterInfo must be the first block.");

        if (reader.gcount() >= block::HeaderSize)
          {
            ntcp2::read_bytes(&message.payload[reader.count()], block_type);

            // only valid block types are RouterInfo, Options, and Padding, see spec
            if (block_type == block::OptionsID)
              read_deserialize(message.opt_block);
            else if (block_type != block::PaddingID)
              ex.throw_ex<std::logic_error>("invalid block type.");

            if (reader.gcount() >= block::HeaderSize)
              {
                ntcp2::read_bytes(&message.payload[reader.count()], block_type);

                if (block_type == block::PaddingID)
                  {
                    read_deserialize(message.pad_block);

                    if (reader.gcount())
                      ex.throw_ex<std::logic_error>(
                          "Padding must be the final block.");
                  }
                else
                  ex.throw_ex<std::logic_error>("invalid block type.");
              }
            else if (reader.gcount() && reader.gcount() < block::HeaderSize)
              ex.throw_ex<std::length_error>("invalid final block size.");
          }
        else if (reader.gcount() && reader.gcount() < block::HeaderSize)
          ex.throw_ex<std::length_error>("invalid second block size.");
      }
    else
      ex.throw_ex<std::logic_error>("payload must contain a RouterInfo block.");

    if (options.m3p2_len != message.payload_size())
      ex.throw_ex<std::logic_error>(
          "part two size must equal to size sent in SessionRequest");
  }
};
}  // namespace ntcp2

#endif  // SRC_NTCP2_SESSION_CONFIRMED_SESSION_CONFIRMED_H_
