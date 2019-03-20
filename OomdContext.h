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

#pragma once

#include <algorithm>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "oomd/include/CgroupPath.h"
#include "oomd/include/Types.h"

namespace Oomd {

struct ActionContext {
  std::string ruleset;
  std::string detectorgroup;
};

class OomdContext {
 public:
  OomdContext() {} // = default warns about dynamic exceptions
  ~OomdContext() = default;
  OomdContext(OomdContext&& other) noexcept;
  OomdContext& operator=(OomdContext&& other);

  /**
   * @returns whether or not OomdContext holds a particular cgroup
   */
  bool hasCgroupContext(const CgroupPath& path) const;

  /**
   * @returns all the stored cgroup paths
   */
  std::vector<CgroupPath> cgroups() const;

  /*
   * @returns a CgroupContext reference associated with @param name
   * @throws std::invalid_argument for missing cgroup
   */
  const CgroupContext& getCgroupContext(const CgroupPath& path);

  /**
   * Assigns a mapping of cgroup -> CgroupContext
   */
  void setCgroupContext(const CgroupPath& path, CgroupContext context);

  /**
   * Manipulates CgroupContexts into helpful other helpful datastructures
   *
   * @param getKey is a lambda that accesses the key you want to reverse sort by
   */
  std::vector<std::pair<CgroupPath, CgroupContext>> reverseSort(
      std::function<double(const CgroupContext& cgroup_ctx)> getKey = nullptr);

  /**
   * In place sorts @param vec. Similar to @method
   * reverseSort(std::function<...>)
   */
  static void reverseSort(
      std::vector<std::pair<CgroupPath, CgroupContext>>& vec,
      std::function<double(const CgroupContext& cgroup_ctx)> getKey);

  /**
   * Dumps OomdContext state to stderr
   */
  void dump();
  static void dumpOomdContext(
      const std::vector<std::pair<CgroupPath, CgroupContext>>& vec,
      const bool skip_negligible = false);

  /**
   * Used to let action plugins know which ruleset and detector group
   * triggered it
   */
  const ActionContext& getActionContext() const;
  void setActionContext(ActionContext context);

 private:
  std::unordered_map<CgroupPath, CgroupContext> memory_state_;
  ActionContext action_context_;
};

} // namespace Oomd
