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

#ifndef _LOADER_SOURCE_DWARF_READER_H_
#define _LOADER_SOURCE_DWARF_READER_H_

#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "elfutils/libdw.h"
#include "sym_addrs.h"

namespace prober {

class DwarfReader {
 public:
  explicit DwarfReader(std::string path);
  absl::Status FindStructs(
      absl::flat_hash_map<std::string, absl::flat_hash_set<std::string> >&
          variables);
  absl::StatusOr<member_var_t> GetMemberVar(std::string struct_name,
                                            std::string member_name);

 private:
  int CheckDie(
      Dwarf_Die* die,
      absl::flat_hash_map<std::string, absl::flat_hash_set<std::string> >&
          variables,
      size_t& count);
  void TraverseDie(
      Dwarf_Die* die,
      absl::flat_hash_map<std::string, absl::flat_hash_set<std::string> >&
          variables,
      size_t& count);
  absl::flat_hash_map<std::string,
                      absl::flat_hash_map<std::string, member_var_t> >
      structs_;
  std::string binary_path_;
};

}  // namespace prober
#endif  // _LOADER_SOURCE_DWARF_READER_H_
