/* copyright (c) 2018, oneiric
 * all rights reserved.
 *
 * redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * this software is provided by the copyright holders and contributors "as is"
 * and any express or implied warranties, including, but not limited to, the
 * implied warranties of merchantability and fitness for a particular purpose are
 * disclaimed. in no event shall the copyright holder or contributors be liable
 * for any direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute goods or
 * services; loss of use, data, or profits; or business interruption) however
 * caused and on any theory of liability, whether in contract, strict liability,
 * or tort (including negligence or otherwise) arising in any way out of the use
 * of this software, even if advised of the possibility of such damage.
*/

#ifndef SRC_NTCP2_SESSION_CREATED_OPTIONS_H_
#define SRC_NTCP2_SESSION_CREATED_OPTIONS_H_

#include "src/ntcp2/session_created/meta.h"

namespace ntcp2
{
namespace session_created
{
/// @brief Container for session request options
struct Options
{
  boost::endian::big_uint16_t pad_len;
  boost::endian::big_uint32_t timestamp;
  std::array<std::uint8_t, ntcp2::meta::session_created::OptionsSize> buf;

  /// @brief Updates session created options
  /// @param pad_len Padding length for the session request
  /// @detail As initiator, must call before calling ProcessMessage
  void update(const boost::endian::big_uint16_t pad_size)
  {
    pad_len = pad_size;
    timestamp = ntcp2::time::now_s();
    serialize();
  }

  /// @brief Write request options to buffer
  void serialize()
  {
    namespace meta = ntcp2::meta::session_created;

    check_params(ntcp2::exception::Exception{"SessionRequest", __func__});

    ntcp2::write_bytes(&buf[meta::PadLengthOffset], pad_len);
    ntcp2::write_bytes(&buf[meta::TimestampOffset], timestamp);
  }

  /// @brief Read request options from buffer
  void deserialize()
  {
    namespace meta = ntcp2::meta::session_created;

    ntcp2::read_bytes(&buf[meta::PadLengthOffset], pad_len);
    ntcp2::read_bytes(&buf[meta::TimestampOffset], timestamp);

    check_params(ntcp2::exception::Exception{"SessionRequest", __func__});
  }

 private:
  void check_params(const ntcp2::exception::Exception& ex)
  {
    if (pad_len > ntcp2::meta::session_created::MaxPaddingSize)
      ex.throw_ex<std::length_error>("invalid padding size.");

    if (!ntcp2::time::check_lag_s(timestamp))
      ex.throw_ex<std::runtime_error>("invalid timestamp.");
  }
};
}  // namespace session_created
}  // namespace ntcp2

#endif  // SRC_NTCP2_SESSION_CREATED_OPTIONS_H_

