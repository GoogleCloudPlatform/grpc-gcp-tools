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

#ifndef _EXPORTERS_OC_GCP_EXPORTER_H_
#define _EXPORTERS_OC_GCP_EXPORTER_H_
#include <memory>
#include <string>
#include <unordered_map>

#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "exporters/exporters_util.h"
#include "google/monitoring/v3/metric_service.grpc.pb.h"
#include "loader/exporter/metric_exporter.h"
#include "opencensus/stats/stats.h"

namespace prober {

enum class AggregationLevel { kHost, kConnection };

class OCGCPMetricExporter : public MetricExporterInterface {
 public:
  OCGCPMetricExporter() = delete;
  OCGCPMetricExporter(std::string project_name, AggregationLevel agg);
  OCGCPMetricExporter(std::string project_name, std::string service_file_path,
                      AggregationLevel agg);

  ~OCGCPMetricExporter() override = default;
  absl::Status Init() override;
  absl::Status CustomLabels(
      const absl::flat_hash_map<std::string, std::string>& labels);
  absl::Status RegisterMetric(std::string name,
                              const MetricDesc& desc) override;
  absl::Status HandleData(std::string metric_name, void* key,
                          void* value) override;
  void Cleanup();

 private:
  void GetTags();
  opencensus::tags::TagMap& GetTagMap(const std::string& uuid);
  void GetMesure(std::string& name, const MetricDesc& desc);
  std::unique_ptr<google::monitoring::v3::MetricService::StubInterface>
  MakeMetricServiceStub(std::string& json_text);
  std::string project_;
  std::string service_file_path_;
  AggregationLevel agg_;
  MetricTimeChecker last_read_;

  absl::flat_hash_map<std::string, opencensus::stats::MeasureInt64> measures_;
  absl::flat_hash_map<std::string, std::string> gce_metadata_;
  absl::flat_hash_map<std::string, opencensus::tags::TagMap*> tag_maps_;
  std::vector<std::pair<opencensus::tags::TagKey, std::string>>
      default_tag_vector_;
  opencensus::tags::TagMap* default_tag_map_;
  absl::flat_hash_map<std::string, MetricDesc> metrics_;
  MetricDataMemory data_memeory_;
};

}  // namespace prober

#endif  // _EXPORTERS_FILE_EXPORTER_H_
