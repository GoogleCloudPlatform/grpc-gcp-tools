// Copyright 2023 Google LLC
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "loader/source/proc_reader.h"

#include <fcntl.h> /* Definition of AT_* constants */
#include <linux/limits.h>
#include <unistd.h>

#include <fstream>
#include <ios>
#include <iostream>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"

namespace prober {

static absl::StatusOr<std::string> readlink(const std::string& link) {
  char buffer[PATH_MAX + 1];
  int dirfd = AT_FDCWD;

  auto bytes = ::readlinkat(dirfd, link.c_str(), &buffer[0], sizeof(buffer));
  if (bytes == -1) {
    return absl::InternalError("Failed to readlinkat");
  }
  return std::string(buffer, bytes);
}

static absl::StatusOr<std::string> get_exe(std::string& task_root) {
  static const std::string EXE_FILE("exe");
  auto path = task_root + EXE_FILE;

  return readlink(path);
}

absl::StatusOr<std::string> get_environ_value(std::string& task_root,
                                              std::string key) {
  static const std::string ENVIRON_FILE("environ");
  auto path = task_root + ENVIRON_FILE;

  std::ifstream ifs;

  ifs.open(task_root, std::ios::in);

  std::string token;
  while (std::getline(ifs, token, '\0').good()) {
    static const char KEY_VALUE_DELIM('=');
    size_t delim = token.find(KEY_VALUE_DELIM);
    if (delim != std::string::npos) {
      if (key == token.substr(0, delim)) {
        return token.substr(delim + 1);
      }
    }
  }
  return absl::NotFoundError("Could Not find key");
}

absl::StatusOr<std::string> ProcReader::GetBinaryPath(pid_t pid) {
  std::string task_root = absl::StrFormat("/proc/%s/", std::to_string(pid));

  auto exe = get_exe(task_root);

  if (!exe.ok()) {
    return absl::NotFoundError("Cound not find path to executable");
  }

  if (exe->at(0) == '/') {
    return exe;
  }

  auto pwd = get_environ_value(task_root, "PWD");
  if (!pwd.ok()) {
    return pwd;
  }

  return *pwd + "/" + *exe;
}

}  // namespace prober
