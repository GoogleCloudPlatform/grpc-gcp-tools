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

#ifndef _SOURCES_COMMON_SYM_TYPES_H_
#define _SOURCES_COMMON_SYM_TYPES_H_

// This is done to make sure headers are self contained.
#ifdef __cplusplus
#include <stdint.h>
#endif

struct go_slice {
  void* ptr;
  int len;
  int cap;
};

struct go_string {
  const char* ptr;
  int64_t len;
};

struct go_interface {
  int64_t type;
  void* ptr;
};

#endif  // _SOURCES_COMMON_SYM_TYPES_H_
