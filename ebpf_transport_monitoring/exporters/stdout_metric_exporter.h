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

#ifndef _EXPORTERS_STDOUT_METRIC_EXPORTER_H_
#define _EXPORTERS_STDOUT_METRIC_EXPORTER_H_

#include <string>
#include <unordered_map>
#include <utility>

#include "absl/status/status.h"
#include "exporters/exporters_util.h"
#include "loader/exporter/data_types.h"
#include "loader/exporter/metric_exporter.h"

namespace prober {

class StdoutMetricExporter : public MetricExporterInterface {
 public:
  StdoutMetricExporter() = default;
  ~StdoutMetricExporter() override = default;
  absl::Status Init() override { return absl::OkStatus(); }

  absl::Status RegisterMetric(std::string name,
                              const MetricDesc& desc) override;
  absl::Status HandleData(std::string metric_name, void* key,
                          void* value) override;
  void Cleanup();

 private:
  absl::flat_hash_map<std::string, MetricDesc> metrics_;
  MetricTimeChecker last_read_;
};

}  // namespace prober

#endif  // EXPORTERS_STDOUT_METRIC_EXPORTER_H_
