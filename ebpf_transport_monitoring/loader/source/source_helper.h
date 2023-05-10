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

#ifndef _LOADER_SOURCE_SOURCE_HELPER_H_
#define _LOADER_SOURCE_SOURCE_HELPER_H_

#include <linux/bpf.h>

#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace prober {

class SourceHelper {
 public:
  static bool TestProgType(bpf_prog_type type);

  /* BPF matches the kernel version while loading uprobes and kprobes.
    In some kernels the VERSION CODE does not match the version 
    mentioned in uname -a. So a better option is to read the kernel
    version code either from vdso or from the file 
    /usr/include/linux/version.h */
  static absl::StatusOr<uint32_t> GetKernelVersion();
  static bool VmlinuxExists(void);
};

} // namespace prober

#endif
