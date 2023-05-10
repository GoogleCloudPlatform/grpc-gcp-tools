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
#include "absl/status/status.h"
#include "elf_reader.h"
#include "loader/source/elf_reader.h"

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cout << "Usage: ./elf_reader_tool <binary_path> [list of functions]"
              << std::endl;
    return 0;
  }

  prober::ElfReader reader(argv[1]);
  absl::flat_hash_map<std::string, uint64_t> functions;
  for (int i = 2; i < argc; ++i) {
    functions[argv[i]] = 0;
  }
  absl::Status status = reader.GetSymbols(functions, prober::ElfReader::kValue);
  if (!status.ok()) {
    std::cout << status;
  }

  for (auto it = functions.begin(); it != functions.end(); ++it) {
    std::cout << it->first << " " << it->second << "\n";
  }

  return 0;
}
