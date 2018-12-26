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

#ifndef SRC_NTCP2_ROUTER_INFO_H_
#define SRC_NTCP2_ROUTER_INFO_H_

#include "src/crypto/meta.h"
#include "src/crypto/radix.h"

#include "src/ntcp2/time.h"

#include "src/ntcp2/router/address.h"
#include "src/ntcp2/router/identity.h"
#include "src/ntcp2/router/meta.h"
#include "src/ntcp2/router/mapping.h"

namespace ntcp2
{
namespace router
{
/// @brief Class for parsing and storing an I2P RouterInfo
class Info
{
  std::shared_ptr<ntcp2::router::Identity> identity_;
  std::uint64_t date_;
  std::vector<ntcp2::router::Address> addresses_;
  ntcp2::router::Mapping options_;
  std::vector<std::uint8_t> transport_;
  ntcp2::crypto::ed25519::Signature signature_;

  // Noise specific
  ntcp2::crypto::x25519::Keypair noise_keys_;
  ntcp2::crypto::aes::IV iv_;

  CryptoPP::SecByteBlock buf_;

  void update_noise_key()
  {
    options_.add(
        std::string("s"),
        ntcp2::crypto::Base64::Encode(
            noise_keys_.pk.data(), noise_keys_.pk.size()));
  }

  void update_iv()
  {
    ntcp2::crypto::RandBytes(iv_.data(), iv_.size());
    options_.add(
        std::string("i"),
        ntcp2::crypto::Base64::Encode(iv_.data(), iv_.size()));
  }

 public:
  /// @brief RouterInfo conversion-ctor (deserializing)
  /// @param buf Buffer containing RouterIdentity bytes
  template <class Buffer>
  explicit Info(const Buffer& buf) : buf_(buf.data(), buf.size())
  {
    deserialize();
  }

  /// @brief RouterInfo conversion-ctor (serializing)
  /// @param ident RouterIdentity (signs/verifies RouterInfo signature)
  /// @param addrs RouterAddress(es) for contacting this RouterInfo
  /// @param opts Router mapping of RouterInfo options
  Info(
      const std::shared_ptr<ntcp2::router::Identity> ident,
      const std::vector<ntcp2::router::Address>& addrs,
      const ntcp2::router::Mapping& opts)
      : identity_(ident),
        date_(ntcp2::time::now_ms()),
        addresses_(addrs),
        options_(opts),
        transport_(
            ntcp2::router::ntcp2_transport.begin(),
            ntcp2::router::ntcp2_transport.end()),
        noise_keys_(crypto::x25519::create_keys())
  {
    namespace meta = ntcp2::meta::router::info;

    const auto total_size = size();
    if (total_size < meta::MinSize || total_size > meta::MaxSize)
      ntcp2::exception::Exception{"RouterInfo", __func__}
          .throw_ex<std::length_error>("invalid size.");

    // update Noise options entries
    update_noise_key();
    update_iv();
    options_.add(std::string("v"), std::string("2"));

    serialize();
  }

  const ntcp2::router::Identity* identity() const noexcept
  {
    return identity_.get();
  }

  const decltype(date_)& date() const noexcept
  {
    return date_;
  }

  const decltype(addresses_)& addresses() const noexcept
  {
    return addresses_;
  }

  decltype(addresses_)& addresses() noexcept
  {
    return addresses_;
  }

  const decltype(options_)& options() const noexcept
  {
    return options_;
  }

  decltype(options_)& options() noexcept
  {
    return options_;
  }

  const decltype(transport_)& transport() const noexcept
  {
    return transport_;
  }

  decltype(transport_)& transport() noexcept
  {
    return transport_;
  }

  const decltype(signature_)& signature() const noexcept
  {
    return signature_;
  }

  const decltype(iv_)& iv() const noexcept
  {
    return iv_;
  }

  const decltype(buf_)& buffer() const noexcept
  {
    return buf_;
  }

  decltype(buf_)& buffer() noexcept
  {
    return buf_;
  }

  /// @brief Get the total size of the RouterInfo
  std::size_t size() const
  {
    namespace meta = ntcp2::meta::router::info;

    std::size_t address_size = 0;
    for (const auto& address : addresses_)
      address_size += address.size();

    return identity_->size() + sizeof(date_) + meta::RouterAddressSizeSize
           + address_size + meta::PeerSizeSize + options_.size()
           + signature_.size();
  }

  /// @brief Serialize RouterInfo data members to buffer
  void serialize()
  {
    namespace meta = ntcp2::meta::router::info;

    const ntcp2::exception::Exception ex{"RouterInfo", __func__};

    buf_.resize(size());

    ntcp2::BytesWriter<decltype(buf_)> writer(buf_);

    identity_->serialize();
    writer.write_data(identity_->buffer());

    date_ = ntcp2::time::now_ms();
    writer.write_bytes(date_);
    writer.write_bytes<std::uint8_t>(addresses_.size());

    for (auto& address : addresses_)
      {
        address.serialize();
        writer.write_data(address.buffer);
      }

    // write zero peer-size, see spec
    writer.write_bytes<std::uint8_t>(0);

    options_.serialize();
    writer.write_data(options_.buffer());

    identity_->signing()->Sign(buf_.data(), writer.count(), signature_);
    writer.write_data(signature_);
  }

  /// @brief Deserialize RouterInfo data members from buffer
  void deserialize()
  {
    namespace meta = ntcp2::meta::router::info;

    const ntcp2::exception::Exception ex{"RouterInfo", __func__};

    ntcp2::BytesReader<decltype(buf_)> reader(buf_);

    if (!identity_)
      {
        identity_ = std::make_shared<ntcp2::router::Identity>(buf_);
        reader.skip_bytes(identity_->size());
      }
    else
      {
        reader.read_data(identity_->buffer());
        identity_->deserialize();
      }

    reader.read_bytes(date_);

    std::uint8_t num_addresses;
    reader.read_bytes(num_addresses);

    // clear current addresses
    addresses_.clear();

    for (std::uint8_t addr = 0; addr < num_addresses; ++addr)
      {
        ntcp2::router::Address address;

        // copy remaining buffer, we don't know address size yet
        const auto addr_begin = buf_.begin() + reader.count();

        if (addr_begin == buf_.end())
          ex.throw_ex<std::logic_error>("addresses overflow the router info.");

        address.buffer.insert(address.buffer.begin(), addr_begin, buf_.end());

        address.deserialize();
        reader.skip_bytes(address.size());

        addresses_.emplace_back(std::move(address));
      }

    reader.skip_bytes(meta::PeerSizeSize);

    if (!reader.gcount())
      ex.throw_ex<std::logic_error>(
          "missing router options size, options, and signature.");

    // read options size before deserializing
    std::uint16_t opt_size;
    ntcp2::read_bytes(buf_.data() + reader.count(), opt_size);

    if (opt_size)
      {
        options_.buffer().resize(sizeof(opt_size) + opt_size);
        reader.read_data(options_.buffer());

        options_.deserialize();
      }
    else
      reader.skip_bytes(sizeof(opt_size));

    reader.read_data(signature_);
    identity_->signing()->Verify(
        buf_.data(), reader.count() - signature_.size(), signature_);
  }
};
}  // namespace router
}  // namespace ntcp2

#endif  // SRC_NTCP2_ROUTER_INFO_H_
