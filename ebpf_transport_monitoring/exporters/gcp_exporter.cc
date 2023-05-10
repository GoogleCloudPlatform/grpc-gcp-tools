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

#include "exporters/gcp_exporter.h"

#include <cstdio>
#include <fstream>
#include <string>
#include <unordered_map>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/substitute.h"
#include "absl/time/time.h"
#include "events.h"
#include "exporters/exporters_util.h"
#include "exporters/gce_metadata.h"
#include "google/cloud/common_options.h"
#include "google/cloud/credentials.h"
#include "google/cloud/logging/logging_service_v2_client.h"
#include "google/cloud/monitoring/metric_client.h"
#include "google/cloud/project.h"
#include "google/protobuf/util/time_util.h"
#include "loader/exporter/data_types.h"

#define LOGGING_INTERVAL absl::Minutes(1)
#define LOGS_PER_REQUEST 199

namespace prober {

namespace logging = ::google::cloud::logging;
namespace monitoring = ::google::cloud::monitoring;

constexpr char kCloudLoggingPathTemplate[] = "projects/$0/logs/";
constexpr char kMetricTypePrefix[] = "custom.googleapis.com";

static google::api::MonitoredResource CreateMontioredResource(
    const std::string& project_id) {
  char hostname[HOST_NAME_MAX];
  gethostname(hostname, HOST_NAME_MAX);
  google::api::MonitoredResource resource;
  auto labels = *resource.mutable_labels();
  resource.set_type("generic_task");
  labels["project_id"] = project_id;
  labels["job"] = "ebpf_prober";
  labels["task_id"] = hostname;
  return resource;
}

GCPLogger::GCPLogger(std::string project_name) : project_(project_name) {
  monitored_resource_ = CreateMontioredResource(project_.FullName());
}

GCPLogger::GCPLogger(std::string project_name, std::string service_file_path)
    : project_(project_name), service_file_path_(service_file_path) {
  monitored_resource_ = CreateMontioredResource(project_.FullName());
}

absl::Status GCPLogger::Init() {
  try {
    if (service_file_path_.empty()) {
      log_client_ = std::make_unique<logging::LoggingServiceV2Client>(
          logging::MakeLoggingServiceV2Connection());
    } else {
      auto creds = std::ifstream(service_file_path_);
      if (!creds.is_open()) {
        return absl::NotFoundError("Service file creds cannot be opened");
      }
      auto contents =
          std::string(std::istreambuf_iterator<char>(creds.rdbuf()), {});
      auto options =
          google::cloud::Options{}.set<google::cloud::UnifiedCredentialsOption>(
              google::cloud::MakeServiceAccountCredentials(contents));

      log_client_ = std::make_unique<logging::LoggingServiceV2Client>(
          logging::MakeLoggingServiceV2Connection(options));
      last_log_sent_ = absl::Now();
    }
  } catch (google::cloud::Status const& status) {
    return absl::InternalError(
        absl::StrCat("Client creation error:", status.message()));
  }

  auto metadata = GCEMetadata::GetGCEMetadata();
  if (metadata.ok()) {
    labels_ = *metadata;
  } else {
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, HOST_NAME_MAX);
    labels_["hostname"] = hostname;
  }
  return absl::OkStatus();
}

absl::Status GCPLogger::RegisterLog(std::string name, LogDesc& log_desc) {
  if (logs_.find(name) != logs_.end()) {
    return absl::AlreadyExistsError("log already registered");
  }
  logs_[name] = true;
  return absl::OkStatus();
}

absl::Status GCPLogger::HandleData(std::string log_name, const void* const data,
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

  auto log_entry = google::logging::v2::LogEntry();
  *log_entry.mutable_resource() = monitored_resource_;

  auto log_time = ExportersUtil::GetLogTime(log_name, data);
  auto timestamp = log_entry.mutable_timestamp();
  const int64_t sec = absl::ToUnixSeconds(log_time);
  timestamp->set_seconds(sec);
  timestamp->set_nanos((log_time - absl::FromUnixSeconds(sec)) /
                       absl::Nanoseconds(1));

  log_entry.set_severity(google::logging::type::LogSeverity::INFO);
  log_entry.set_text_payload(*log_data);

  log_entries_.emplace_back(log_entry);

  // TODO: This should Ideally be done as async but for now so we let it be.
  if (log_entries_.size() > LOGS_PER_REQUEST ||
      (absl::Now() - last_log_sent_) > LOGGING_INTERVAL) {
    std::map<std::string, std::string> labels;
    labels["source"] = "ebpf";
    for (auto& label : labels_) {
      labels[label.first] = labels[label.second];
    }
    last_log_sent_ = absl::Now();
    auto response = log_client_->WriteLogEntries(
        absl::StrCat(
            absl::Substitute(kCloudLoggingPathTemplate, project_.project_id()),
            "ebpf_prober"),
        monitored_resource_, labels, log_entries_);
    log_entries_.clear();
    if (!response.ok()) {
      return absl::InternalError(response.status().message());
    }
  }
  return absl::OkStatus();
}

GCPMetricExporter::GCPMetricExporter(std::string project_name)
    : project_(project_name) {
  monitored_resource_ = CreateMontioredResource(project_.FullName());
}

GCPMetricExporter::GCPMetricExporter(std::string project_name,
                                     std::string service_file_path)
    : project_(project_name), service_file_path_(service_file_path) {
  monitored_resource_ = CreateMontioredResource(project_.FullName());
}

absl::Status GCPMetricExporter::Init() {
  try {
    if (service_file_path_.empty()) {
      metric_client_ = std::make_unique<monitoring::MetricServiceClient>(
          monitoring::MakeMetricServiceConnection());
    } else {
      auto creds = std::ifstream(service_file_path_);
      if (!creds.is_open()) {
        return absl::NotFoundError("Service file creds cannot be opened");
      }
      auto contents =
          std::string(std::istreambuf_iterator<char>(creds.rdbuf()), {});
      auto options =
          google::cloud::Options{}.set<google::cloud::UnifiedCredentialsOption>(
              google::cloud::MakeServiceAccountCredentials(contents));

      metric_client_ = std::make_unique<monitoring::MetricServiceClient>(
          monitoring::MakeMetricServiceConnection(options));
    }
  } catch (google::cloud::Status const& status) {
    return absl::InternalError(
        absl::StrCat("Client creation error:", status.message()));
  }

  auto metadata = GCEMetadata::GetGCEMetadata();
  if (metadata.ok()) {
    labels_ = *metadata;
  } else {
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, HOST_NAME_MAX);
    labels_["hostname"] = hostname;
  }

  return absl::OkStatus();
}

static std::string GcpDataTypeString(MetricDataType type) {
  switch (type) {
    case MetricDataType::kbytes:
      return "By";
    case MetricDataType::kkbytes:
      return "kBy";
    case MetricDataType::kmbytes:
      return "MBy";
    case MetricDataType::kgbytes:
      return "GBy";
    case MetricDataType::kbits:
      return "bit";
    case MetricDataType::kkbits:
      return "kbit";
    case MetricDataType::kmbits:
      return "Mbits";
    case MetricDataType::kgbits:
      return "Gbits";
  }
  return "";
}

static std::string GcpGetUnitString(MetricUnit_t unit) {
  switch (unit.type) {
    case MetricUnitType::kTime:
      return TimeTypeString(unit.time);
    case MetricUnitType::kData:
      return GcpDataTypeString(unit.data);
    case MetricUnitType::kNone:
      return "";
  }
  return "";
}

static google::api::MetricDescriptor::MetricKind GetGCPMetricKind(
    MetricKind kind) {
  switch (kind) {
    case MetricKind::kNone:
      // This is an error case we must bail out earlier. However, for now we
      // will
      //  assume it is a gauge.
    case MetricKind::kDistribution:
    case MetricKind::kGauge:
      return google::api::MetricDescriptor::GAUGE;
    case MetricKind::kDelta:
      return google::api::MetricDescriptor::DELTA;
    case MetricKind::kCumulative:
      return google::api::MetricDescriptor::CUMULATIVE;
  }
  return google::api::MetricDescriptor::GAUGE;
}

absl::StatusOr<google::api::MetricDescriptor>
GCPMetricExporter::CreateMetricDesciptor(std::string name,
                                         const MetricDesc& desc) {
  google::monitoring::v3::CreateMetricDescriptorRequest request;
  request.set_name(project_.FullName());

  google::api::MetricDescriptor* metric_descriptor =
      request.mutable_metric_descriptor();

  metric_descriptor->set_type(
      absl::StrCat(kMetricTypePrefix, "/ebpf_prober/", name));
  metric_descriptor->set_description("");
  metric_descriptor->clear_labels();
  auto metric_label = metric_descriptor->add_labels();
  metric_label->set_key("conn_id");
  metric_label->set_value_type(google::api::LabelDescriptor::STRING);
  metric_label->set_description("Connection Id");

  for (auto& label : labels_) {
    metric_label->set_key(label.first);
    metric_label->set_value_type(google::api::LabelDescriptor::STRING);
  }
  // For now everything is a GAUGE with INT64 but will change in the future
  metric_descriptor->set_metric_kind(GetGCPMetricKind(desc.kind));
  metric_descriptor->set_value_type(google::api::MetricDescriptor::INT64);
  metric_descriptor->set_unit(GcpGetUnitString(desc.unit));
  auto response = metric_client_->CreateMetricDescriptor(request);
  if (!response.ok()) {
    return absl::InternalError(
        absl::StrCat("Cannot create descriptor", response.status().message()));
  }
  return *response;
}

absl::Status GCPMetricExporter::RegisterMetric(std::string name,
                                               const MetricDesc& desc) {
  if (metrics_.find(name) != metrics_.end()) {
    return absl::AlreadyExistsError("metric already registered");
  }

  if (desc.kind == MetricKind::kNone) {
    return absl::InternalError("Invalid Metric Kind");
  }

  auto response = CreateMetricDesciptor(name, desc);
  if (!response.ok()) {
    return absl::InternalError(
        absl::StrCat("Metric creation error:", response.status().message()));
  }
  metrics_[name] = {};
  metrics_[name].desc = desc;
  metrics_[name].metric_descriptor = *response;

  return absl::OkStatus();
}

absl::Status GCPMetricExporter::HandleData(std::string metric_name, void* key,
                                           void* value) {
  auto it = metrics_.find(metric_name);
  if (it == metrics_.end()) {
    return absl::NotFoundError("metric_name not found");
  }

  metric_format_t* metric = (metric_format_t*)value;
  auto metric_desc = metrics_.find(metric_name);

  auto uuid = correlator_->GetUUID(*(uint64_t*)key);
  if (!uuid.ok()) {
    return absl::OkStatus();
  }

  // This line also checks if a metric was just read.
  auto old_timestamp =
      last_read_.CheckMetricTime(metric_name, *uuid, metric->timestamp);
  if (!old_timestamp.ok()) {
    return absl::OkStatus();
  }

  google::monitoring::v3::CreateTimeSeriesRequest request;
  request.set_name(project_.FullName());

  auto time_series = request.add_time_series();

  auto metric_series = time_series->mutable_metric();
  metric_series->set_type(metric_desc->second.metric_descriptor.type());
  auto labels = metric_series->mutable_labels();

  labels->insert({"conn_id", *uuid});

  for (auto& label : labels_) {
    labels->insert({label.first, label.second});
  }

  time_series->mutable_resource()->set_type("global");
  auto point = time_series->add_points();
  point->mutable_value()->set_int64_value(ExportersUtil::GetMetric(
      &(metric->data), metric_desc->second.desc.value_type));

  absl::Time t1;
  int64_t sec;
  if (metric_desc->second.desc.kind == MetricKind::kDelta) {
    auto timestamp = point->mutable_interval()->mutable_start_time();
    t1 = ExportersUtil::GetTimeFromBPFns(*old_timestamp);
    sec = absl::ToUnixSeconds(t1);
    timestamp->set_seconds(sec);
    timestamp->set_nanos((t1 - absl::FromUnixSeconds(sec)) /
                         absl::Nanoseconds(1));
  }

  auto end_timestamp = last_read_.GetMetricTime(metric_name, *uuid);
  if (!end_timestamp.ok()) {
    std::cout << "Invalid end time" << std::endl;
    return absl::OkStatus();
  }
  auto timestamp = point->mutable_interval()->mutable_end_time();
  t1 = ExportersUtil::GetTimeFromBPFns(*end_timestamp);
  sec = absl::ToUnixSeconds(t1);
  timestamp->set_seconds(sec);
  timestamp->set_nanos((t1 - absl::FromUnixSeconds(sec)) /
                       absl::Nanoseconds(1));

  auto start_timestamp = last_read_.GetMetricStartTime(metric_name, *uuid);
  if (!start_timestamp.ok()) {
    std::cout << "Invalid start time" << std::endl;
    return absl::OkStatus();
  }

  if (metric_desc->second.desc.kind == MetricKind::kCumulative) {
    auto timestamp = point->mutable_interval()->mutable_start_time();
    t1 = absl::FromUnixNanos(*start_timestamp);
    sec = absl::ToUnixSeconds(t1);
    timestamp->set_seconds(sec);
    timestamp->set_nanos((t1 - absl::FromUnixSeconds(sec)) /
                         absl::Nanoseconds(1));
  }

  auto status = metric_client_->CreateTimeSeries(request);
  if (!status.ok()) {
    return absl::InternalError(
        absl::StrCat("sending time series:", status.message()));
  }
  return absl::OkStatus();
}

void GCPMetricExporter::Cleanup() {
  auto uuids = last_read_.GetUUID();
  for (auto uuid : uuids) {
    if (!correlator_->CheckUUID(uuid)) {
      last_read_.DeleteValue(uuid);
    }
  }
}

}  // namespace prober
