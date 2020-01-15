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

#include "oomd/util/Fs.h"

#include <dirent.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <cinttypes>
#include <deque>
#include <fstream>
#include <sstream>
#include <utility>

#include "oomd/include/Assert.h"
#include "oomd/util/Util.h"

namespace {

enum class PsiFormat {
  MISSING = 0, // File is missing
  INVALID, // Don't recognize
  EXPERIMENTAL, // Experimental format
  UPSTREAM, // Upstream kernel format
};

PsiFormat getPsiFormat(const std::vector<std::string>& lines) {
  if (lines.size() == 0) {
    return PsiFormat::MISSING;
  }

  const auto& first = lines[0];
  if (Oomd::Util::startsWith("some", first) && lines.size() >= 2) {
    return PsiFormat::UPSTREAM;
  } else if (Oomd::Util::startsWith("aggr", first) && lines.size() >= 3) {
    return PsiFormat::EXPERIMENTAL;
  } else {
    return PsiFormat::INVALID;
  }
}

}; // namespace

namespace Oomd {

struct Fs::DirEnts Fs::readDir(const std::string& path, int flags) {
  DIR* d;
  struct Fs::DirEnts de;

  d = ::opendir(path.c_str());
  if (!d) {
    return de;
  }

  while (struct dirent* dir = ::readdir(d)) {
    if (dir->d_name[0] == '.') {
      continue;
    }

    /*
     * Optimisation: Avoid doing lstat calls if kernfs gives us back d_type.
     * This actually can be pretty useful, since avoiding lstat()ing everything
     * can reduce oomd CPU usage by ~10% on a reasonably sized cgroup
     * hierarchy.
     */
    if ((flags & DirEntFlags::DE_FILE) && dir->d_type == DT_REG) {
      de.files.push_back(dir->d_name);
      continue;
    }
    if ((flags & DirEntFlags::DE_DIR) && dir->d_type == DT_DIR) {
      de.dirs.push_back(dir->d_name);
      continue;
    }

    auto file = path + "/" + dir->d_name;
    struct stat buf;
    int ret = ::lstat(file.c_str(), &buf);
    if (ret == -1) {
      continue;
    }

    if ((flags & DirEntFlags::DE_FILE) && (buf.st_mode & S_IFREG)) {
      de.files.push_back(dir->d_name);
    }
    if ((flags & DirEntFlags::DE_DIR) && (buf.st_mode & S_IFDIR)) {
      de.files.push_back(dir->d_name);
    }
  }

  ::closedir(d);
  return de;
}

bool Fs::isDir(const std::string& path) {
  struct stat sb;
  if (!::stat(path.c_str(), &sb) && S_ISDIR(sb.st_mode)) {
    return true;
  }

  return false;
}

/*
 * Return if a string might have something special for fnmatch.
 *
 * This function is simple and can return false-positives, but not
 * false-negatives -- that is, true means "maybe", and false means false.
 * That's ok, since this is only used for optimisations.
 */
bool Fs::hasGlob(const std::string& s) {
  return s.find_first_of("*[?") != std::string::npos;
}

std::unordered_set<std::string> Fs::resolveWildcardPath(
    const CgroupPath& cgpath) {
  std::string path = cgpath.absolutePath();
  std::unordered_set<std::string> ret;
  if (path.empty()) {
    return ret;
  }

  auto parts = Util::split(path, '/');
  OCHECK_EXCEPT(!parts.empty(), "No parts in " + path);

  std::deque<std::pair<std::string, size_t>> queue;

  // Add initial path piece to begin search on. Start at root.
  queue.emplace_back("/", 0);

  // Perform a DFS on the entire search space. Note that we pattern
  // match at each level of the provided path to eliminate "dead"
  // branches. The algorithm is still O(N) but in practice this will
  // prevent us from enumerating every entry in the root filesystem.
  //
  // We choose DFS because we predict the FS tree is wider than it
  // is tall. DFS will use less space than BFS in this case because
  // it does not need to store every node at each level of the tree.
  while (!queue.empty()) {
    const auto front = queue.front(); // copy
    queue.pop_front();

    // Optimisation: If there's no glob and we're not at the end, it must be
    // intended to be a single dir. It doesn't matter if it actually *is* in
    // reality, because if it doesn't exist we'll fail later on.
    if (front.second < parts.size() - 1 && !Fs::hasGlob(parts[front.second])) {
      queue.emplace_front(
          front.first + parts[front.second] + "/", front.second + 1);
      continue;
    }

    // We can't continue BFS if we've hit a regular file
    if (!isDir(front.first)) {
      continue;
    }

    auto de = readDir(front.first, DE_FILE | DE_DIR);
    de.files.reserve(de.files.size() + de.dirs.size());
    de.files.insert(de.files.end(), de.dirs.begin(), de.dirs.end());

    for (const auto& entry : de.files) {
      if (::fnmatch(parts[front.second].c_str(), entry.c_str(), 0) == 0) {
        if (front.second == parts.size() - 1) {
          // We have reached a leaf, add it to the return set
          ret.emplace(front.first + entry);
        } else if (front.second < parts.size() - 1) {
          // There are still more parts of the provided path to search.
          //
          // Note that we add the '/' at the end of the new path. This makes
          // the recursive case easier, as the recursive case need only
          // add the next part of the path on. Also note the 'emplace_front'
          // that makes the deque into a stack (thus the DFS).
          queue.emplace_front(front.first + entry + "/", front.second + 1);
        }
      }
    }
  }

  return ret;
}

void Fs::removePrefix(std::string& str, const std::string& prefix) {
  if (str.find(prefix) != std::string::npos) {
    // Strip the leading './' if it exists and we haven't been explicitly
    // told to strip it
    if (str.find("./") == 0 && prefix.find("./") != 0) {
      str.erase(0, 2);
    }

    str.erase(0, prefix.size());
  }
}

/* Reads a file and returns a newline separated vector of strings */
std::vector<std::string> Fs::readFileByLine(const std::string& path) {
  std::ifstream f(path, std::ios::in);
  if (!f.is_open()) {
    return {};
  }

  std::string s;
  std::vector<std::string> v;
  while (std::getline(f, s)) {
    v.push_back(std::move(s));
  }

  return v;
}

std::vector<std::string> Fs::readControllers(const std::string& path) {
  std::vector<std::string> controllers;
  auto lines = readFileByLine(path + "/" + kControllersFile);
  if (!lines.size()) {
    return controllers;
  }

  controllers = Util::split(lines[0], ' ');

  return controllers;
}

std::vector<int> Fs::getPids(const std::string& path, bool recursive) {
  std::vector<int> pids;
  auto de = readDir(path, DE_FILE | DE_DIR);
  if (std::any_of(de.files.begin(), de.files.end(), [](const std::string& s) {
        return s == kProcsFile;
      })) {
    auto str_pids = readFileByLine(path + "/" + kProcsFile);
    for (const auto& sp : str_pids) {
      pids.push_back(std::stoi(sp));
    }
  }

  if (recursive) {
    for (const auto& dir : de.dirs) {
      auto recursive_pids = getPids(path + "/" + dir, true);
      pids.insert(pids.end(), recursive_pids.begin(), recursive_pids.end());
    }
  }

  return pids;
}

std::string Fs::pressureTypeToString(PressureType type) {
  switch (type) {
    case PressureType::SOME:
      return "some";
    case PressureType::FULL:
      return "full";
  }
  throw std::runtime_error("Invalid PressureType. Code should not be reached");
}

ResourcePressure Fs::readRespressure(
    const std::string& path,
    PressureType type) {
  auto lines = readFileByLine(path);

  auto type_name = pressureTypeToString(type);
  size_t pressure_line_index = 0;
  switch (type) {
    case PressureType::SOME:
      pressure_line_index = 0;
      break;
    case PressureType::FULL:
      pressure_line_index = 1;
      break;
  }

  switch (getPsiFormat(lines)) {
    case PsiFormat::UPSTREAM: {
      // Upstream v4.16+ format
      //
      // some avg10=0.22 avg60=0.17 avg300=1.11 total=58761459
      // full avg10=0.22 avg60=0.16 avg300=1.08 total=58464525
      std::vector<std::string> toks =
          Util::split(lines[pressure_line_index], ' ');
      OCHECK_EXCEPT(
          toks[0] == type_name, bad_control_file(path + ": invalid format"));
      std::vector<std::string> avg10 = Util::split(toks[1], '=');
      OCHECK_EXCEPT(
          avg10[0] == "avg10", bad_control_file(path + ": invalid format"));
      std::vector<std::string> avg60 = Util::split(toks[2], '=');
      OCHECK_EXCEPT(
          avg60[0] == "avg60", bad_control_file(path + ": invalid format"));
      std::vector<std::string> avg300 = Util::split(toks[3], '=');
      OCHECK_EXCEPT(
          avg300[0] == "avg300", bad_control_file(path + ": invalid format"));
      std::vector<std::string> total = Util::split(toks[4], '=');
      OCHECK_EXCEPT(
          total[0] == "total", bad_control_file(path + ": invalid format"));

      return ResourcePressure{
          std::stof(avg10[1]),
          std::stof(avg60[1]),
          std::stof(avg300[1]),
          std::chrono::microseconds(std::stoull(total[1])),
      };
    }
    case PsiFormat::EXPERIMENTAL: {
      // Old experimental format
      //
      // aggr 316016073
      // some 0.00 0.03 0.05
      // full 0.00 0.03 0.05
      std::vector<std::string> toks =
          Util::split(lines[pressure_line_index + 1], ' ');
      OCHECK_EXCEPT(
          toks[0] == type_name, bad_control_file(path + ": invalid format"));

      return ResourcePressure{
          std::stof(toks[1]),
          std::stof(toks[2]),
          std::stof(toks[3]),
          std::nullopt,
      };
    }
    case PsiFormat::MISSING:
      // Missing the control file
      throw bad_control_file(path + ": missing file");
    case PsiFormat::INVALID:
      throw bad_control_file(path + ": invalid format");
  }

  // To silence g++ compiler warning about enums
  throw std::runtime_error("Not all enums handled");
}

int64_t Fs::readMemcurrent(const std::string& path) {
  if (path == "/") {
    auto meminfo = getMeminfo("/proc/meminfo");
    return meminfo["MemTotal"] - meminfo["MemFree"];
  } else {
    auto lines = readFileByLine(path + "/" + kMemCurrentFile);
    OCHECK_EXCEPT(lines.size() == 1, bad_control_file(path + ": missing file"));
    return static_cast<int64_t>(std::stoll(lines[0]));
  }
}

ResourcePressure Fs::readMempressure(
    const std::string& path,
    PressureType type) {
  if (path == "/") {
    try {
      return readRespressure("/proc/pressure/memory", type);
    } catch (const bad_control_file& e) {
      return readRespressure("/proc/mempressure", type);
    }
  } else {
    return readRespressure(path + "/" + kMemPressureFile, type);
  }
}

int64_t Fs::readMinMaxLowHigh(
    const std::string& path,
    const std::string& file) {
  auto lines = readFileByLine(path + "/" + file);
  OCHECK_EXCEPT(lines.size() == 1, bad_control_file(path + ": missing file"));
  if (lines[0] == "max") {
    return std::numeric_limits<int64_t>::max();
  }
  return static_cast<int64_t>(std::stoll(lines[0]));
}

int64_t Fs::readMemlow(const std::string& path) {
  return Fs::readMinMaxLowHigh(path, kMemLowFile);
}

int64_t Fs::readMemhigh(const std::string& path) {
  return Fs::readMinMaxLowHigh(path, kMemHighFile);
}

int64_t Fs::readMemmax(const std::string& path) {
  return Fs::readMinMaxLowHigh(path, kMemMaxFile);
}

int64_t Fs::readMemhightmp(const std::string& path) {
  auto lines = readFileByLine(path + "/" + kMemHighTmpFile);
  OCHECK_EXCEPT(lines.size() == 1, bad_control_file(path + ": missing file"));
  auto tokens = Util::split(lines[0], ' ');
  OCHECK_EXCEPT(
      tokens.size() == 2, bad_control_file(path + ": invalid format"));
  if (tokens[0] == "max") {
    return std::numeric_limits<int64_t>::max();
  }
  return static_cast<int64_t>(std::stoll(tokens[0]));
}

int64_t Fs::readMemmin(const std::string& path) {
  return Fs::readMinMaxLowHigh(path, kMemMinFile);
}

int64_t Fs::readSwapCurrent(const std::string& path) {
  auto lines = readFileByLine(path + "/" + kMemSwapCurrentFile);

  // The swap controller can be disabled via CONFIG_MEMCG_SWAP=n
  if (lines.size() == 1) {
    return static_cast<int64_t>(std::stoll(lines[0]));
  } else {
    return 0;
  }
}

std::unordered_map<std::string, int64_t> Fs::getVmstat(
    const std::string& path) {
  auto lines = readFileByLine(path);
  std::unordered_map<std::string, int64_t> map;
  char space{' '};

  for (auto& line : lines) {
    std::stringstream ss(line);
    std::string item;

    // get key
    std::getline(ss, item, space);
    std::string key{item};

    // insert value into map
    std::getline(ss, item, space);
    map[key] = static_cast<int64_t>(std::stoll(item));
  }

  return map;
}

std::unordered_map<std::string, int64_t> Fs::getMeminfo(
    const std::string& path) {
  char name[256] = {0};
  uint64_t val;
  std::unordered_map<std::string, int64_t> map;

  auto lines = readFileByLine(path);
  for (auto& line : lines) {
    int ret =
        sscanf(line.c_str(), "%255[^:]:%*[ \t]%" SCNu64 "%*s\n", name, &val);
    if (ret == 2) {
      map[name] = val * 1024;
    }
  }

  return map;
}

std::unordered_map<std::string, int64_t> Fs::getMemstatLike(
    const std::string& file) {
  char name[256] = {0};
  uint64_t val;
  std::unordered_map<std::string, int64_t> map;

  auto lines = readFileByLine(file);
  for (const auto& line : lines) {
    int ret = sscanf(line.c_str(), "%255s %" SCNu64 "\n", name, &val);
    if (ret == 2) {
      map[name] = val;
    }
  }

  return map;
}

std::unordered_map<std::string, int64_t> Fs::getMemstat(
    const std::string& path) {
  return getMemstatLike(path + "/" + kMemStatFile);
}

ResourcePressure Fs::readIopressure(
    const std::string& path,
    PressureType type) {
  if (path == "/") {
    return readRespressure("/proc/pressure/io", type);
  } else {
    return readRespressure(path + "/" + kIoPressureFile, type);
  }
}

IOStat Fs::readIostat(const std::string& path) {
  const auto& io_stat_path = path + "/" + kIoStatFile;
  auto lines = readFileByLine(io_stat_path);
  std::vector<DeviceIOStat> io_stat;
  io_stat.reserve(lines.size());

  for (const auto& line : lines) {
    // format
    //
    // 0:0 rbytes=0 wbytes=0 rios=0 wios=0 dbytes=0 dios=0
    DeviceIOStat dev_io_stat;
    int major, minor;
    int ret = sscanf(
        line.c_str(),
        "%d:%d rbytes=%" SCNd64 " wbytes=%" SCNd64 " rios=%" SCNd64
        " wios=%" SCNd64 " dbytes=%" SCNd64 " dios=%" SCNd64 "\n",
        &major,
        &minor,
        &dev_io_stat.rbytes,
        &dev_io_stat.wbytes,
        &dev_io_stat.rios,
        &dev_io_stat.wios,
        &dev_io_stat.dbytes,
        &dev_io_stat.dios);

    OCHECK_EXCEPT(ret == 8, bad_control_file(path + ": invalid format"));
    dev_io_stat.dev_id = std::to_string(major) + ":" + std::to_string(minor);
    io_stat.push_back(dev_io_stat);
  }
  return io_stat;
}

void Fs::writeMemhigh(const std::string& path, int64_t value) {
  char buf[1024];
  buf[0] = '\0';
  auto file_name = path + "/" + kMemHighFile;
  auto fd = ::open(file_name.c_str(), O_WRONLY);
  if (fd < 0) {
    throw bad_control_file(
        file_name + ": open failed: " + ::strerror_r(errno, buf, sizeof(buf)));
  }
  auto val_str = std::to_string(value);
  auto ret = Util::writeFull(fd, val_str.c_str(), val_str.size());
  ::close(fd);
  if (ret < 0) {
    throw bad_control_file(
        file_name + ": write failed: " + ::strerror_r(errno, buf, sizeof(buf)));
  }
}

void Fs::writeMemhightmp(
    const std::string& path,
    int64_t value,
    std::chrono::microseconds duration) {
  char buf[1024];
  buf[0] = '\0';
  auto file_name = path + "/" + kMemHighTmpFile;
  auto fd = ::open(file_name.c_str(), O_WRONLY);
  if (fd < 0) {
    throw bad_control_file(
        file_name + ": open failed: " + ::strerror_r(errno, buf, sizeof(buf)));
  }
  auto val_str = std::to_string(value) + " " + std::to_string(duration.count());
  auto ret = Util::writeFull(fd, val_str.c_str(), val_str.size());
  ::close(fd);
  if (ret < 0) {
    throw bad_control_file(
        file_name + ": write failed: " + ::strerror_r(errno, buf, sizeof(buf)));
  }
}

int64_t Fs::getNrDyingDescendants(const std::string& path) {
  auto map = getMemstatLike(path + "/" + kCgroupStatFile);
  // Will return 0 for missing entries
  return map["nr_dying_descendants"];
}

bool Fs::setxattr(
    const std::string& path,
    const std::string& attr,
    const std::string& val) {
  int ret = ::setxattr(path.c_str(), attr.c_str(), val.c_str(), val.size(), 0);
  if (ret == -1) {
    return false;
  }
  return true;
}

std::string Fs::getxattr(const std::string& path, const std::string& attr) {
  std::string val;

  int size = ::getxattr(path.c_str(), attr.c_str(), nullptr, 0);
  if (size <= 0) {
    return val;
  }

  val.resize(size);
  ::getxattr(path.c_str(), attr.c_str(), &val[0], val.size());
  return val;
}

bool Fs::isUnderParentPath(
    const std::string& parent_path,
    const std::string& path) {
  if (parent_path.empty() || path.empty()) {
    return false;
  }

  auto parent_parts = Util::split(parent_path, '/');
  auto path_parts = Util::split(path, '/');
  int i = 0;

  if (path_parts.size() < parent_parts.size()) {
    return false;
  }

  for (const auto& parts : parent_parts) {
    if (path_parts[i] != parts) {
      return false;
    }
    i++;
  }
  return true;
}

std::string Fs::getCgroup2MountPoint(const std::string& path) {
  auto lines = readFileByLine(path);
  for (auto& line : lines) {
    auto parts = Util::split(line, ' ');
    if (parts.size() > 2) {
      if (parts[2] == "cgroup2") {
        return parts[1] + '/';
      }
    }
  }
  return "";
}

DeviceType Fs::getDeviceType(
    const std::string& dev_id,
    const std::string& path) {
  const auto deviceTypeFile =
      path + "/" + dev_id + "/" + kDeviceTypeDir + "/" + kDeviceTypeFile;
  auto lines = readFileByLine(deviceTypeFile);
  if (lines.size() == 1) {
    if (lines[0] == "1") {
      return DeviceType::HDD;
    } else if (lines[0] == "0") {
      return DeviceType::SSD;
    }
  }
  throw bad_control_file(deviceTypeFile + ": invalid format");
}

} // namespace Oomd
