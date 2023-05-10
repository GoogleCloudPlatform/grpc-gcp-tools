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

#include "loader/source/source_helper.h"

#include <fstream>

#include "absl/strings/numbers.h"
#include "loader/source/elf_reader.h"
#include "re2/re2.h"

#include "bpf/bpf.h"
#include "bpf/libbpf.h"

namespace prober{

bool SourceHelper::TestProgType(bpf_prog_type type) {
  return libbpf_probe_bpf_prog_type(type, NULL) == 1;
}

static absl::StatusOr<uint32_t> get_kernel_version_file() {
  std::ifstream file("/usr/include/linux/version.h");
  if (!file) {
    return absl::InternalError("Could not open version header file");
  }

  std::string contents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

  int retVal;
  std::string version;
  if (RE2::PartialMatch(contents, "#define\\s+LINUX_VERSION_CODE\\s+(\\d+)", &version)) {
    if (!absl::SimpleAtoi(version, &retVal)){
      file.close();
      return absl::InternalError("Could not conver version to integer");
    }
    else {
      file.close();
      return retVal;
    }
  }

  file.close();
  return absl::NotFoundError("Could not find version from file");
}

/*
  In older kernels while loading kprobes the kernel versions are checked.
  Some kernels don't report versions in a straight forward way via uname.
  
  Following https://github.com/iovisor/bpftrace/issues/274

  The best way is to read kernel version is reading it in the notes of vdso.
  If that fails we can grep it from the file "/usr/include/linux/version.h"
*/
absl::StatusOr<uint32_t> SourceHelper::GetKernelVersion(){
  auto version  = prober::ElfReader::GetKernelVersion();
  if (version.ok()){
    return *version;
  }
  std::cerr << "WARN: " << version.status() << std::endl;

  version = get_kernel_version_file();
  if (version.ok()) {
    return *version;
  }
  
  return absl::InternalError("Could not find version");
}

bool SourceHelper::VmlinuxExists() {
  if (!access("/sys/kernel/btf/vmlinux", R_OK)) return true;
  return false;
}

}
