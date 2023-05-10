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

#ifndef _SOURCES_H2_GO_GRPC_SOURCE_H_
#define _SOURCES_H2_GO_GRPC_SOURCE_H_

#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "loader/source/data_source.h"
#include "loader/source/elf_reader.h"
#include "sources/common/h2_symaddrs.h"

namespace prober {
class H2GoGrpcSource : public DataSource {
 public:
  H2GoGrpcSource();
  absl::Status AddPID(uint64_t pid);
  absl::Status LoadMaps() override;
  ~H2GoGrpcSource() override;
  std::string ToString() const override { return "H2GoGrpcSource"; };

 private:
  absl::Status CreateProbes(
      ElfReader* elf_reader, uint64_t pid, std::string& path,
      absl::flat_hash_map<std::string, uint64_t>& functions,
      const char* probe_func);
  absl::Status RegisterProbes(ElfReader* elf_reader, std::string& path,
                              uint64_t pid);
  absl::flat_hash_map<uint64_t, h2_cfg_t> bpf_cfg_;
};

}  // namespace prober

#endif  // _SOURCES_H2_GO_GRPC_SOURCE_H_
