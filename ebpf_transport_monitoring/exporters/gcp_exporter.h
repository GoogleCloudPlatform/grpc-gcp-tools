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

#ifndef _EXPORTERS_GCP_EXPORTER_H_
#define _EXPORTERS_GCP_EXPORTER_H_

#include <memory>
#include <string>
#include <unordered_map>

#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "exporters/exporters_util.h"
#include "google/cloud/logging/logging_service_v2_client.h"
#include "google/cloud/monitoring/metric_client.h"
#include "google/cloud/project.h"
#include "loader/exporter/log_exporter.h"
#include "loader/exporter/metric_exporter.h"

namespace prober {

class GCPLogger : public LogExporterInterface {
 public:
  GCPLogger() = delete;
  GCPLogger(std::string project_name);
  GCPLogger(std::string project_name, std::string service_file_path);
  ~GCPLogger() override = default;
  absl::Status Init() override;
  absl::Status RegisterLog(std::string name, LogDesc& log_desc) override;
  absl::Status HandleData(std::string log_name, const void* const data,
                          const uint32_t size) override;

 private:
  std::vector<google::logging::v2::LogEntry> log_entries_;
  std::unordered_map<std::string, bool> logs_;
  google::cloud::Project project_;
  std::string service_file_path_;
  google::api::MonitoredResource monitored_resource_;
  std::unique_ptr<google::cloud::logging::LoggingServiceV2Client> log_client_;
  absl::Time last_log_sent_;
  absl::flat_hash_map<std::string, std::string> labels_;
};

class GCPMetricExporter : public MetricExporterInterface {
 public:
  GCPMetricExporter() = delete;
  GCPMetricExporter(std::string project_name);
  GCPMetricExporter(std::string project_name, std::string service_file_path);

  ~GCPMetricExporter() override = default;
  absl::Status Init() override;
  absl::Status RegisterMetric(std::string name,
                              const MetricDesc& desc) override;
  absl::Status HandleData(std::string metric_name, void* key,
                          void* value) override;
  void Cleanup();

 private:
  typedef struct __GCP_metric_metadata {
    MetricDesc desc;
    google::api::MetricDescriptor metric_descriptor;
  } GCP_metric_metadata_t;

  MetricTimeChecker last_read_;

  absl::StatusOr<google::api::MetricDescriptor> CreateMetricDesciptor(
      std::string name, const MetricDesc& desc);

  absl::flat_hash_map<std::string, GCP_metric_metadata_t> metrics_;

  google::cloud::Project project_;
  std::string service_file_path_;
  google::api::MonitoredResource monitored_resource_;
  std::unique_ptr<::google::cloud::monitoring::MetricServiceClient>
      metric_client_;
  absl::flat_hash_map<std::string, std::string> labels_;
};

}  // namespace prober

#endif  // _EXPORTERS_FILE_EXPORTER_H_
