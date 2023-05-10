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

#ifndef _LOADER_EXPORTER_LOG_EXPORTER_H_
#define _LOADER_EXPORTER_LOG_EXPORTER_H_

#include <string>

#include "absl/status/status.h"
#include "loader/correlator/correlator.h"
#include "loader/exporter/data_types.h"
#include "loader/exporter/handlers.h"

namespace prober {

class LogExporterInterface : public LogHandlerInterface {
 public:
  virtual absl::Status Init() = 0;
  virtual absl::Status RegisterLog(std::string name, LogDesc& log_desc) = 0;
  virtual ~LogExporterInterface() {}
  void RegisterCorrelator(CorrelatorInterface* correlator) {
    correlator_ = correlator;
  }

 protected:
  CorrelatorInterface* correlator_;
};

}  // namespace prober

#endif  // _LOADER_EXPORTER_LOG_EXPORTER_H_
