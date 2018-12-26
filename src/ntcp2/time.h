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

#ifndef SRC_NTCP2_TIME_H_
#define SRC_NTCP2_TIME_H_

#include <chrono>

namespace ntcp2
{
namespace meta
{
namespace time
{
enum Limits : std::uint32_t
{
  LagDelta = 120,
  MaxLagDelta = 3 * LagDelta,
};
}  // namespace time
}  // namespace meta
namespace time
{
/// @brief Get current time in seconds
inline std::uint32_t now_s()
{
  return std::chrono::steady_clock::now().time_since_epoch().count()
         * std::chrono::steady_clock::period::num
         / std::chrono::steady_clock::period::den;
}

/// @brief Get current time in milliseconds
inline std::uint64_t now_ms()
{
  return std::chrono::steady_clock::now().time_since_epoch().count();
}

/// @brief Check if timestamp delta (seconds) is within valid range
/// @param time Timestamp to check
inline bool check_lag_s(const std::uint32_t time)
{
  return now_s() - time <= ntcp2::meta::time::MaxLagDelta;
}
}  // namespace time
}  // namespace ntcp2

#endif  // SRC_NTCP2_TIME_H_
