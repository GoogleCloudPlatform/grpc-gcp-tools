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

#include "exporters/stdout_event_logger.h"

#include <cstdio>
#include <optional>
#include <ostream>
#include <string>
#include <unordered_map>

#include "absl/status/status.h"
#include "exporters/exporters_util.h"

namespace prober {

absl::Status StdoutEventExporter::RegisterLog(std::string name,
                                              LogDesc& log_desc) {
  if (logs_.find(name) != logs_.end()) {
    return absl::AlreadyExistsError("log already registered");
  }
  logs_[name] = true;
  return absl::OkStatus();
}

absl::Status StdoutEventExporter::HandleData(std::string log_name,
                                             const void* const data,
                                             const uint32_t size) {
  absl::Status status;
  if (logs_.find(log_name) == logs_.end()) {
    return absl::NotFoundError("log not registered");
  }

  auto conn_id = ExportersUtil::GetLogConnId(log_name, data);

  auto uuid = correlator_->GetUUID(conn_id);

  if (!uuid.ok()) {
    return absl::OkStatus();
  }

  auto log_data = ExportersUtil::GetLogString(log_name, *uuid, data);
  if (!log_data.ok()) {
    return log_data.status();
  }
  std::cout << *log_data << std::endl;
  return absl::OkStatus();
}

}  // namespace prober
