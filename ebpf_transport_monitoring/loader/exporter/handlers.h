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

#ifndef _LOADER_EXPORTER_HANDLERS_H_
#define _LOADER_EXPORTER_HANDLERS_H_

#include <string>

#include "absl/status/status.h"
#include "loader/exporter/handlers.h"

namespace prober {

class LogHandlerInterface {
 public:
  virtual absl::Status HandleData(std::string log_name, const void* const data,
                                  const uint32_t size) = 0;
};

class MetricHandlerInterface {
 public:
  virtual void Cleanup() = 0;
  virtual absl::Status HandleData(std::string metric_name, void* key,
                                  void* value) = 0;

};

}  // namespace prober

#endif
