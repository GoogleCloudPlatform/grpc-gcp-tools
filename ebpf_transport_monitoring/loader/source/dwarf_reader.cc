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

#include "loader/source/dwarf_reader.h"

#include <fcntl.h>
#include <unistd.h>

#include <cstddef>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "dwarf.h"
#include "elfutils/libdw.h"
#include "sym_addrs.h"

namespace prober {

static uint64_t GetOffset(Dwarf_Attribute* attr) {
  uint64_t offset;
  unsigned int form;

  form = dwarf_whatform(attr);
  if (form == DW_FORM_data1 || form == DW_FORM_data2 || form == DW_FORM_data4 ||
      form == DW_FORM_data8 || form == DW_FORM_udata) {
    dwarf_formudata(attr, &offset);
  } else if (form == DW_FORM_sdata) {
    Dwarf_Sword soffset;
    dwarf_formsdata(attr, &soffset);
    if (soffset < 0) {
    }
    offset = (uint64_t)soffset;
  } /*else {
    
      Dwarf_Locdesc **locdescs;
      Dwarf_Signed len;
      if (dwarf_loclist_n(attr, &locdescs, &len,  &error) == DW_DLV_ERROR) {
            printf("unsupported member offset\n");
      }
      if (len != 1
          || locdescs[0]->ld_cents != 1
          || (locdescs[0]->ld_s[0]).lr_atom != DW_OP_plus_uconst) {
            printf("unsupported location expression\n");
      }
      offset = (locdescs[0]->ld_s[0]).lr_number; 
  } */
  return offset;
}

int DwarfReader::CheckDie(
    Dwarf_Die* die,
    absl::flat_hash_map<std::string, absl::flat_hash_set<std::string> >&
        variables,
    size_t& count) {
  Dwarf_Attribute attr;
  Dwarf_Die curr_die;

  if (dwarf_tag(die) == DW_TAG_structure_type) {
    const char* name = dwarf_diename(die);
    if (name == nullptr) {
      goto descend;
    }

    std::string die_name(name);
    absl::flat_hash_map<std::string,
                        absl::flat_hash_set<std::string> >::iterator it;
    for (it = variables.begin(); it != variables.end(); it++) {
      size_t pos = die_name.find(it->first);
      // The second condition is to avoid matching to no named structs
      if (pos != std::string::npos &&
          (pos + it->first.length() == die_name.length())) {
        break;
      }
    }

    if (it == variables.end()) {
      goto descend;
    }

    if (dwarf_child(die, &curr_die) != 0) {
      goto descend;
    }

    // Increment the count so we can bail out when we have found all information
    //  we are looking for.
    count++;
    do {
      name = dwarf_diename(&curr_die);
      if (name == nullptr) {
        continue;
      }

      auto itin = it->second.find(name);
      if (itin == it->second.end()) {
        continue;
      }

      structs_[it->first][name] = {0, 0};

      if (dwarf_hasattr(&curr_die, DW_AT_data_member_location) != 0) {
        dwarf_attr(&curr_die, DW_AT_data_member_location, &attr);
        structs_[it->first][name].offset = GetOffset(&attr);
      }

      Dwarf_Die type_die;
      if (dwarf_hasattr(&curr_die, DW_AT_type) != 0) {
        dwarf_attr(&curr_die, DW_AT_type, &attr);
        if (dwarf_formref_die(&attr, &type_die) == nullptr) {
          continue;
        }
        structs_[it->first][name].size = dwarf_bytesize(&type_die);
      }
    } while (dwarf_siblingof(&curr_die, &curr_die) == 0);
  }

// Check if we need to descend the DWARF tree based on tag
descend:
  switch (dwarf_tag(die)) {
      /* DIEs with addresses we need to traverse  */
    case DW_TAG_compile_unit:
    case DW_TAG_module:
    case DW_TAG_lexical_block:
    case DW_TAG_entry_point:
      return 1;

    /* Other DIEs we have no reason to descend.  */
    default:
      break;
  }

  return 0;
}

void DwarfReader::TraverseDie(
    Dwarf_Die* die,
    absl::flat_hash_map<std::string, absl::flat_hash_set<std::string> >&
        variables,
    size_t& count) {
  int descend = CheckDie(die, variables, count);

  if (descend == 0) {
    return;
  }

  Dwarf_Die iter_mem;
  Dwarf_Die* iter = &iter_mem;
  if (dwarf_child(die, &iter_mem) != 0) {
    return;
  }

  do {
    TraverseDie(iter, variables, count);
    if (count == variables.size()) {
      break;
    }
  } while (dwarf_siblingof(iter, iter) == 0);
}

DwarfReader::DwarfReader(std::string path) : binary_path_(path) {}

absl::Status DwarfReader::FindStructs(
    absl::flat_hash_map<std::string, absl::flat_hash_set<std::string> >&
        variables) {
  int fd = open(binary_path_.c_str(), O_RDONLY);
  if (fd < 0) {
    return absl::NotFoundError("Binary Path could not be opened");
  }

  Dwarf* dwarf = dwarf_begin(fd, DWARF_C_READ);
  if (dwarf == NULL) {
    return absl::InternalError(
        absl::StrFormat("Dwarf Error: %s", dwarf_errmsg(-1)));
  }

  Dwarf_Off off = 0;
  Dwarf_Off next_off = 0;
  size_t header_size = 0;
  size_t count = 0;

  while (dwarf_nextcu(dwarf, off, &next_off, &header_size, NULL, NULL, NULL) ==
         0) {
    Dwarf_Die die_mem;
    Dwarf_Die* die = dwarf_offdie(dwarf, off + header_size, &die_mem);
    TraverseDie(die, variables, count);
    off = next_off;
  }

  dwarf_end(dwarf);
  close(fd);
  return absl::OkStatus();
}

absl::StatusOr<member_var_t> DwarfReader::GetMemberVar(
    std::string struct_name, std::string member_name) {
  auto it = structs_.find(struct_name);
  if (it == structs_.end()) {
    return absl::NotFoundError(
        absl::StrFormat("struct %s not found with DWARF", struct_name));
  }

  auto itin = it->second.find(member_name);
  if (itin == it->second.end()) {
    return absl::NotFoundError(absl::StrFormat(
        "member %s of struct %s not found with DWARF", member_name));
  }

  return itin->second;
}

}  // namespace prober
