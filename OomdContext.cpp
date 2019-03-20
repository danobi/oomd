/*
 * Copyright (C) 2018-present, Facebook, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "oomd/OomdContext.h"
#include "oomd/Log.h"
#include "oomd/util/Fs.h"

#include <exception>

namespace Oomd {

OomdContext& OomdContext::operator=(OomdContext&& other) {
  memory_state_ = std::move(other.memory_state_);
  action_context_ = other.action_context_;
  return *this;
}

OomdContext::OomdContext(OomdContext&& other) noexcept {
  memory_state_ = std::move(other.memory_state_);
  action_context_ = other.action_context_;
}

bool OomdContext::hasCgroupContext(const CgroupPath& path) const {
  return memory_state_.find(path) != memory_state_.end();
}

std::vector<CgroupPath> OomdContext::cgroups() const {
  std::vector<CgroupPath> keys;

  for (const auto& pair : memory_state_) {
    keys.emplace_back(pair.first);
  }

  return keys;
}

const CgroupContext& OomdContext::getCgroupContext(const CgroupPath& path) {
  if (!hasCgroupContext(path)) {
    throw std::invalid_argument("Cgroup not present");
  }

  return memory_state_[path];
}

void OomdContext::setCgroupContext(
    const CgroupPath& path,
    CgroupContext context) {
  memory_state_[path] = context;
}

std::vector<std::pair<CgroupPath, CgroupContext>> OomdContext::reverseSort(
    std::function<double(const CgroupContext& cc)> getKey) {
  std::vector<std::pair<CgroupPath, CgroupContext>> vec;

  for (const auto& pair : memory_state_) {
    vec.emplace_back(
        std::pair<CgroupPath, CgroupContext>{pair.first, pair.second});
  }

  if (getKey) {
    reverseSort(vec, getKey);
  }

  return vec;
}

void OomdContext::reverseSort(
    std::vector<std::pair<CgroupPath, CgroupContext>>& vec,
    std::function<double(const CgroupContext& cc)> getKey) {
  std::sort(
      vec.begin(),
      vec.end(),
      [getKey](
          std::pair<CgroupPath, CgroupContext>& first,
          std::pair<CgroupPath, CgroupContext>& second) {
        // Want to sort in reverse order (largest first), so return
        // true if first element is ordered before second element
        return getKey(first.second) > getKey(second.second);
      });
}

const ActionContext& OomdContext::getActionContext() const {
  return action_context_;
}

void OomdContext::setActionContext(ActionContext context) {
  action_context_ = context;
}

void OomdContext::dump() {
  dumpOomdContext(reverseSort());
}

void OomdContext::dumpOomdContext(
    const std::vector<std::pair<CgroupPath, CgroupContext>>& vec,
    const bool skip_negligible) {
  OLOG << "Dumping OomdContext: ";
  for (const auto& ms : vec) {
    if (skip_negligible) {
      // don't show if <1% pressure && <.1% usage
      auto meminfo = Fs::getMeminfo();
      const float press_min = 1;
      const int64_t mem_min = meminfo["MemTotal"] / 1000;
      const int64_t swap_min = meminfo["SwapTotal"] / 1000;

      if (!(ms.second.pressure.sec_10 >= press_min ||
            ms.second.pressure.sec_60 >= press_min ||
            ms.second.pressure.sec_600 >= press_min ||
            ms.second.io_pressure.sec_10 >= press_min ||
            ms.second.io_pressure.sec_60 >= press_min ||
            ms.second.io_pressure.sec_600 >= press_min ||
            ms.second.current_usage > mem_min ||
            ms.second.average_usage > mem_min ||
            ms.second.swap_usage > swap_min)) {
        continue;
      }
    }

    OLOG << "name=" << ms.first.relativePath();
    OLOG << "  pressure=" << ms.second.pressure.sec_10 << ":"
         << ms.second.pressure.sec_60 << ":" << ms.second.pressure.sec_600
         << "-" << ms.second.io_pressure.sec_10 << ":"
         << ms.second.io_pressure.sec_60 << ":"
         << ms.second.io_pressure.sec_600;
    OLOG << "  mem=" << (ms.second.current_usage >> 20) << "MB"
         << " mem_avg=" << (ms.second.average_usage >> 20) << "MB"
         << " mem_low=" << (ms.second.memory_low >> 20) << "MB"
         << " swap=" << (ms.second.swap_usage >> 20) << "MB";
  }
}

} // namespace Oomd
