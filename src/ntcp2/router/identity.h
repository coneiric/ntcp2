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

#ifndef SRC_NTCP2_ROUTER_IDENTITY_H_
#define SRC_NTCP2_ROUTER_IDENTITY_H_

#include "src/crypto/meta.h"
#include "src/crypto/rand.h"
#include "src/crypto/elgamal.h"
#include "src/crypto/sign.h"

#include "src/ntcp2/router/meta.h"
#include "src/ntcp2/router/certificate.h"

namespace ntcp2
{
namespace router
{
/// @brief Idenity hash alias for correctness, usability
/// @detail Wiping identity hashes from memory removes traces of contacted routers
using IdentHash = CryptoPP::FixedSizeSecBlock<std::uint8_t, ntcp2::crypto::hash::Sha256Len>;

/// @brief Convenience class for processing RouterIdentity crypto
class Crypto
{
  ntcp2::crypto::elgamal::Encryptor enc_;
  std::unique_ptr<ntcp2::crypto::elgamal::Decryptor> dec_;

 public:
  explicit Crypto(const ntcp2::crypto::elgamal::Keypair& keys)
      : enc_(keys.pk), dec_(new ntcp2::crypto::elgamal::Decryptor(keys.sk))
  {
  }

  explicit Crypto(const ntcp2::crypto::pk::ElGamal& key) : enc_(key) {}

  /// @brief Convenience function to encrypt message using ElGamal
  /// @param ciphertext Output buffer for ciphertext
  /// @param plaintext Input buffer for plaintext
  /// @param zero_pad Flag for zero-padded ciphertext
  void Encrypt(
      ntcp2::crypto::elgamal::Ciphertext& ciphertext,
      const ntcp2::crypto::elgamal::Plaintext& plaintext,
      const bool zero_pad)
  {
    enc_.Encrypt(ciphertext, plaintext, zero_pad);
  }

  /// @brief Convenience function to decrypt message using ElGamal
  /// @param plaintext Output buffer for plaintext
  /// @param ciphertext Input buffer for ciphertext
  /// @param zero_pad Flag for zero-padded ciphertext
  void Decrypt(
      ntcp2::crypto::elgamal::Plaintext& plaintext,
      const ntcp2::crypto::elgamal::Ciphertext& ciphertext,
      const bool zero_pad)
  {
    if (!dec_)
      ntcp2::exception::Exception{"Identity: Crypto", __func__}
          .throw_ex<std::logic_error>("null decryptor.");

    dec_->Decrypt(plaintext, ciphertext, zero_pad);
  }

  /// @brief Get the public key
  decltype(auto) pub_key() const noexcept
  {
    return enc_.pub_key();
  }

  /// @brief Rekey the encryption public key
  /// @param key ElGamal public key
  void rekey(const ntcp2::crypto::pk::ElGamal& key)
  {
    enc_.rekey(key);
  }

  /// @brief Rekey the crypto keypair
  /// @param keys ElGamal keypair
  void rekey(const ntcp2::crypto::elgamal::Keypair& keys)
  {
    enc_.rekey(keys.pk);

    if (!dec_)
      dec_ = std::make_unique<ntcp2::crypto::elgamal::Decryptor>(keys.sk);
    else
      dec_->rekey(keys.sk);
  }
};

/// @brief Convenience class for processing RouterIdentity signatures
class Signing
{
  std::unique_ptr<ntcp2::crypto::ed25519::Signer> signer_;
  ntcp2::crypto::ed25519::Verifier verifier_;

 public:
  explicit Signing(const ntcp2::crypto::ed25519::Keypair& keys)
      : signer_(new ntcp2::crypto::ed25519::Signer(keys)), verifier_(keys.pk)
  {
  }

  explicit Signing(const ntcp2::crypto::pk::Ed25519& pk) : verifier_(pk)
  {
  }

  /// @brief Convenience function to Ed25519 sign a message
  template <class MessageIt>
  void Sign(
      const MessageIt data,
      const std::size_t size,
      ntcp2::crypto::ed25519::Signature& sig) const
  {
    if (!signer_)
      ntcp2::exception::Exception{"Router: Signing", __func__}
          .throw_ex<std::logic_error>("null signer.");

    signer_->Sign(data, size, sig.data());
  }

  /// @brief Convenience function to verify an Ed25519 signed message
  template <class MessageIt>
  bool Verify(
      const MessageIt data,
      const std::size_t size,
      const ntcp2::crypto::ed25519::Signature& sig) const
  {
    return verifier_.Verify(data, size, sig.data());
  }

  /// @brief Rekey the verifier public key
  void rekey(const ntcp2::crypto::pk::Ed25519& key)
  {
    if (signer_)
      ntcp2::exception::Exception{"Router: Signing", __func__}
          .throw_ex<std::logic_error>(
              "private key present. Create a new object, or rekey with "
              "a keypair.");

    verifier_.rekey(key);
  }

  /// @brief Rekey the signing keypair
  void rekey(const ntcp2::crypto::ed25519::Keypair& keys)
  {
    if (!signer_)
      signer_ = std::make_unique<ntcp2::crypto::ed25519::Signer>(keys.sk);
    else
      signer_->rekey(keys.sk);

    verifier_.rekey(keys.pk);
  }

  /// @brief Get the public key
  decltype(auto) pub_key() const noexcept
  {
    return verifier_.pub_key();
  }

  /// @brief Get the signature length
  decltype(auto) sig_len() const noexcept
  {
    return verifier_.sig_len();
  }
};

/// @brief Class for I2P RouterIdentity
class Identity
{
  std::array<std::uint8_t, ntcp2::meta::router::identity::PaddingSize> padding_;
  ntcp2::router::Certificate cert_;
  std::unique_ptr<ntcp2::router::Crypto> crypto_;
  std::unique_ptr<ntcp2::router::Signing> signing_;
  ntcp2::router::IdentHash hash_;
  CryptoPP::FixedSizeSecBlock<
      std::uint8_t,
      ntcp2::meta::router::identity::DefaultSize>
      buf_;

 public:
  Identity()
  {
    ntcp2::crypto::RandBytes(padding_.data(), padding_.size());

    create_keys();

    serialize();
  }

  /// @brief Converting ctor for deserializing from a buffer
  /// @param buffer Buffer containing raw router identity
  template <class Buffer>
  explicit Identity(const Buffer& buf)
  {
    namespace meta = ntcp2::meta::router::identity;

    if (buf.size() != meta::DefaultSize)
      ntcp2::exception::Exception{"RouterIdentity", __func__}
          .throw_ex<std::length_error>("invalid identity size.");

    std::copy(buf.begin(), buf.end(), buf_.begin());

    deserialize();
  }

  /// @brief Converting-ctor (copy) for serializing from a crypto + signing key
  /// @param ck Encryption public key
  /// @param sk Signing public key
  Identity(
      const ntcp2::crypto::pk::ElGamal& ck,
      const ntcp2::crypto::pk::Ed25519& sk)
      : crypto_(new Crypto(ck)), signing_(new Signing(sk))
  {
    ntcp2::crypto::RandBytes(padding_.data(), padding_.size());

    serialize();
  }

  /// @brief Converting-ctor (copy) for serializing from a crypto + signing keypairs
  /// @param crypto_keys Encryption keypair
  /// @param sign_keys Signing keypair
  Identity(
      const ntcp2::crypto::elgamal::Keypair& crypto_keys,
      const ntcp2::crypto::ed25519::Keypair& sign_keys)
      : crypto_(new Crypto(crypto_keys)), signing_(new Signing(sign_keys))
  {
    ntcp2::crypto::RandBytes(padding_.data(), padding_.size());

    serialize();
  }

  /// @brief Get a const reference to the buffer
  const decltype(buf_)& buffer() const noexcept
  {
    return buf_;
  }

  /// @brief Get a non-const reference to the buffer
  decltype(buf_)& buffer() noexcept
  {
    return buf_;
  }

  /// @brief Get a const reference to the crypto class
  decltype(auto) crypto() const noexcept
  {
    return crypto_.get();
  }

  /// @brief Get a const pointer to the signing class
  decltype(auto) signing() const noexcept
  {
    return signing_.get();
  }

  /// @brief Get a const reference to the certificate
  const decltype(cert_)& cert() const noexcept
  {
    return cert_;
  }

  /// @brief Get the total size of the router identity
  std::size_t size() const noexcept
  {
    return crypto_->pub_key().size() + padding_.size()
           + signing_->pub_key().size() + cert_.length;
  }

  /// @brief Get the padding size
  std::uint8_t padding_len() const noexcept
  {
    return padding_.size();
  }

  /// @brief Get a const reference to the Identity hash
  const decltype(hash_)& ident_hash() const noexcept
  {
    return hash_;
  }

  /// @brief Calculate a new Identity hash from the current buffer
  void update_hash()
  {
    CryptoPP::SHA256().CalculateDigest(hash_.data(), buf_.data(), buf_.size());
  }

  /// @brief Serialize the router identity to buffer
  void serialize()
  {
    namespace meta = ntcp2::meta::router::identity;

    ntcp2::BytesWriter<decltype(buf_)> writer(buf_);

    writer.write_data(crypto_->pub_key());
    writer.write_data(padding_);
    writer.write_data(signing_->pub_key());

    cert_.serialize();
    writer.write_data(cert_.buffer);

    update_hash();
  }

  /// @brief Deserialize the router identity from buffer
  void deserialize()
  {
    namespace meta = ntcp2::meta::router::identity;

    ntcp2::BytesReader<decltype(buf_)> reader(buf_);

    ntcp2::crypto::pk::ElGamal crypto_key;
    reader.read_data(crypto_key);

    reader.read_bytes(padding_);

    ntcp2::crypto::pk::Ed25519 sign_key;
    reader.read_data(sign_key);

    reader.read_data(cert_.buffer);

    crypto_ = std::make_unique<Crypto>(crypto_key);
    signing_ = std::make_unique<Signing>(sign_key);

    cert_.deserialize();

    update_hash();
  }

 private:
  void create_keys()
  {
    namespace ed25519 =  ntcp2::crypto::ed25519;
    namespace elgamal =  ntcp2::crypto::elgamal;

    // create the crypto and signing keys
    crypto_ = std::make_unique<Crypto>(elgamal::create_keys());
    signing_ = std::make_unique<Signing>(ed25519::create_keys());
  }
};
}  // namespace router
}  // namespace ntcp2

#endif  // SRC_NTCP2_ROUTER_IDENTITY_H_
