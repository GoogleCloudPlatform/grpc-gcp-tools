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

#include <iostream>
#include <ostream>
#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "loader/source/dwarf_reader.h"
#include "sym_addrs.h"

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cout << "Usage: ./dwarf_reader_tool <binary_path> <struct_name> [list "
                 "of members]"
              << std::endl;
    return 0;
  }

  prober::DwarfReader reader(argv[1]);
  absl::flat_hash_map<std::string, absl::flat_hash_set<std::string> > structs;
  absl::flat_hash_set<std::string> members;
  for (int i = 3; i < argc; ++i) {
    members.insert(argv[i]);
  }

  structs[argv[2]] = members;
  absl::Status status = reader.FindStructs(structs);
  if (!status.ok()) {
    std::cout << status;
  }

  for (auto it = structs.begin(); it != structs.end(); ++it) {
    std::cout << it->first << ": \n";
    for (auto itin = it->second.begin(); itin != it->second.end(); ++itin) {
      auto mem = reader.GetMemberVar(it->first, *itin);
      if (!mem.ok()) {
        std::cout << "\t" << *itin << " not found" << std::endl;
        continue;
      }
      std::cout << "\t" << *itin << " " << mem->offset << " " << mem->size
                << std::endl;
    }
  }

  return 0;
}
