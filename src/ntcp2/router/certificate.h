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

#ifndef SRC_NTCP2_ROUTER_CERTIFICATE_H_
#define SRC_NTCP2_ROUTER_CERTIFICATE_H_

#include <type_traits>

#include "src/exception/exception.h"

#include "src/ntcp2/bytes.h"

#include "src/ntcp2/router/meta.h"

namespace ntcp2
{
namespace router
{
/// @brief Container and processor of router certificates
struct Certificate
{
  ntcp2::meta::router::cert::CertTypes cert_type;
  std::uint16_t length;
  ntcp2::meta::router::cert::SigningTypes sign_type;
  ntcp2::meta::router::cert::CryptoTypes crypto_type;
  std::array<std::uint8_t, ntcp2::meta::router::cert::KeyCertSize> buffer;

  Certificate()
      : cert_type(ntcp2::meta::router::cert::KeyCert),
        length(ntcp2::meta::router::cert::KeyCertSize),
        sign_type(ntcp2::meta::router::cert::Ed25519Sign),
        crypto_type(ntcp2::meta::router::cert::ElGamalCrypto)
  {
    serialize();
  }

  /// @brief Serialize the certificate to buffer
  void serialize()
  {
    namespace meta = ntcp2::meta::router::cert;

    const ntcp2::exception::Exception ex{"Router: Certificate", __func__};

    check_params(ex);

    ntcp2::BytesWriter<decltype(buffer)> writer(buffer);

    writer.write_bytes(cert_type);
    writer.write_bytes(length);
    writer.write_bytes(sign_type);
    writer.write_bytes(crypto_type);
  }

  /// @brief Deserialize the certificate from buffer
  void deserialize()
  {
    namespace meta = ntcp2::meta::router::cert;

    const ntcp2::exception::Exception ex{"Router: Certificate", __func__};

    ntcp2::BytesReader<decltype(buffer)> reader(buffer);

    reader.read_bytes(cert_type);
    reader.read_bytes(length);
    reader.read_bytes(sign_type);
    reader.read_bytes(crypto_type);

    check_params(ex);
  }

 private:
  void check_params(const ntcp2::exception::Exception& ex)
  {
    namespace meta = ntcp2::meta::router::cert;

    if (cert_type != meta::KeyCert)
      ex.throw_ex<std::runtime_error>("invalid certificate type.");

    if (length != meta::KeyCertSize)
      ex.throw_ex<std::runtime_error>("invalid certificate length.");

    if (sign_type != meta::Ed25519Sign)
      ex.throw_ex<std::runtime_error>("invalid signing type.");

    if (crypto_type != meta::ElGamalCrypto)
      ex.throw_ex<std::runtime_error>("invalid crypto type.");
  }
};
}  // namespace router
}  // namespace ntcp2

#endif  // SRC_NTCP2_ROUTER_CERTIFICATE_H_
