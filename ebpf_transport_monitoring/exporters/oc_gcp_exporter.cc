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

#include "exporters/oc_gcp_exporter.h"

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
#include "google/monitoring/v3/metric_service.grpc.pb.h"
#include "grpcpp/grpcpp.h"
#include "grpcpp/security/credentials.h"
#include "oc_gcp_exporter.h"
#include "opencensus/exporters/stats/stackdriver/stackdriver_exporter.h"
#include "opencensus/stats/stats.h"

#define LOGGING_INTERVAL absl::Minutes(1)
#define LOGS_PER_REQUEST 199

namespace prober {

using ::opencensus::stats::Aggregation;
using ::opencensus::stats::AggregationWindow;
using ::opencensus::stats::BucketBoundaries;
using ::opencensus::stats::MeasureInt64;
using ::opencensus::stats::ViewDescriptor;

const char kStatsPrefix[] = "ebpf_prober/";
constexpr char kGoogleStackdriverStatsAddress[] = "monitoring.googleapis.com";

static std::string OCDataTypeString(MetricDataType type) {
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

Aggregation DataDistributionAggregation() {
  return Aggregation::Distribution(BucketBoundaries::Explicit(
      {0, 1024, 2048, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216,
       67108864, 268435456, 1073741824, 4294967296}));
}

Aggregation TimeDistributionAggregation() {
  return Aggregation::Distribution(BucketBoundaries::Explicit(
      {0,   0.01, 0.05, 0.1,  0.3,   0.6,   0.8,   1,     2,   3,   4,
       5,   6,    8,    10,   13,    16,    20,    25,    30,  40,  50,
       65,  80,   100,  130,  160,   200,   250,   300,   400, 500, 650,
       800, 1000, 2000, 5000, 10000, 20000, 50000, 100000}));
}

Aggregation CountDistributionAggregation() {
  return Aggregation::Distribution(BucketBoundaries::Exponential(17, 1.0, 2.0));
}

OCGCPMetricExporter::OCGCPMetricExporter(std::string project_name,
                                         AggregationLevel agg)
    : project_(project_name), agg_(agg), default_tag_map_(nullptr) {}

OCGCPMetricExporter::OCGCPMetricExporter(std::string project_name,
                                         std::string service_file_path,
                                         AggregationLevel agg)
    : project_(project_name),
      service_file_path_(service_file_path),
      agg_(agg),
      default_tag_map_(nullptr) {}

std::unique_ptr<google::monitoring::v3::MetricService::StubInterface>
OCGCPMetricExporter::MakeMetricServiceStub(std::string& json_text) {
  grpc::ChannelArguments args;
  args.SetUserAgentPrefix("stackdriver_exporter");
  // The credential file path is configured by environment variable
  // GOOGLE_APPLICATION_CREDENTIALS
  std::shared_ptr<::grpc::ChannelCredentials> credential;
  if (service_file_path_.empty()) {
    credential = ::grpc::GoogleDefaultCredentials();
  } else {
    auto jwt_creds = ::grpc::ServiceAccountJWTAccessCredentials(json_text);
    auto ssl_creds = ::grpc::SslCredentials(grpc::SslCredentialsOptions{});
    credential = ::grpc::CompositeChannelCredentials(ssl_creds, jwt_creds);
  }
  auto channel = ::grpc::CreateCustomChannel(kGoogleStackdriverStatsAddress,
                                             credential, args);
  return google::monitoring::v3::MetricService::NewStub(channel);
}

absl::Status OCGCPMetricExporter::Init() {
  GetTags();

  std::string json_text;
  if (!service_file_path_.empty()) {
    auto creds = std::ifstream(service_file_path_);
    if (!creds.is_open()) {
      return absl::NotFoundError("Service file creds cannot be opened");
    }
    json_text = std::string(std::istreambuf_iterator<char>(creds.rdbuf()), {});
  }
  opencensus::exporters::stats::StackdriverOptions stats_opts;
  stats_opts.project_id = project_;
  // We add a lot of detail already. Don't need to add more cardinality.
  stats_opts.opencensus_task = "ebpf_prober";
  stats_opts.metric_service_stub = MakeMetricServiceStub(json_text);

  opencensus::exporters::stats::StackdriverExporter::Register(
      std::move(stats_opts));

  return absl::OkStatus();
}

static std::string OCGetUnitString(MetricUnit_t unit) {
  switch (unit.type) {
    case MetricUnitType::kTime:
      // we always convert to miliseconds
      return TimeTypeString(MetricTimeType::kmsec);
    case MetricUnitType::kData:
      return OCDataTypeString(unit.data);
    case MetricUnitType::kNone:
      return "";
  }
  return "";
}

void OCGCPMetricExporter::GetMesure(std::string& name, const MetricDesc& desc) {
  measures_.insert({name, opencensus::stats::MeasureInt64::Register(
                              absl::StrCat(kStatsPrefix, "measure/", name), "",
                              OCGetUnitString(desc.unit))});
}

void OCGCPMetricExporter::GetTags() {
  auto metadata = GCEMetadata::GetGCEMetadata();
  if (!metadata.ok()) {
    std::cerr << "WARN: Unable to find GCE metadata: " << metadata.status()
              << std::endl;
  } else {
    gce_metadata_ = *metadata;
  }

  if (!gce_metadata_.empty()) {
    for (auto it : gce_metadata_) {
      auto tag = opencensus::tags::TagKey::Register(it.first);
      default_tag_vector_.push_back(std::make_pair(tag, it.second));
    }
  } else {
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, HOST_NAME_MAX);
    auto tag = opencensus::tags::TagKey::Register("hostname");
    default_tag_vector_.push_back(std::make_pair(tag, hostname));
  }

  default_tag_map_ = new opencensus::tags::TagMap(default_tag_vector_);
}

absl::StatusOr<opencensus::stats::Aggregation> GetAggregation(
    std::string& name, const MetricDesc& desc) {
  switch (desc.kind) {
    case MetricKind::kGauge:
      return Aggregation::LastValue();

    case MetricKind::kDelta:
      return Aggregation::Sum();

    case MetricKind::kCumulative:
      return Aggregation::Sum();

    case MetricKind::kDistribution:
      switch (desc.unit.type) {
        case MetricUnitType::kTime:
          return prober::TimeDistributionAggregation();

        case MetricUnitType::kData:
          return prober::DataDistributionAggregation();

        case MetricUnitType::kNone:
          return prober::CountDistributionAggregation();
      }

    default:
      break;
  }
  return absl::InternalError("Unknown Aggregation");
}

absl::Status OCGCPMetricExporter::RegisterMetric(std::string name,
                                                 const MetricDesc& desc) {
  if (measures_.find(name) != measures_.end()) {
    return absl::AlreadyExistsError("metric already registered");
  }

  if (correlator_ == nullptr) {
    return absl::InternalError(
        "Correlator needs to be registerd before metrics");
  }

  if (desc.kind == MetricKind::kNone) {
    return absl::InternalError("Invalid Metric Kind");
  }

  metrics_[name] = desc;

  GetMesure(name, desc);
  auto descriptor =
      opencensus::stats::ViewDescriptor()
          .set_name(absl::StrCat(kStatsPrefix, "desc/", name))
          .set_measure(absl::StrCat(kStatsPrefix, "measure/", name));

  auto agg = GetAggregation(name, desc);
  if (!agg.ok()) {
    return agg.status();
  }

  descriptor.set_aggregation(*agg);
  descriptor.set_expiry_duration(absl::Seconds(120));

  for (auto& tag : default_tag_vector_) {
    descriptor.add_column(tag.first);
  }

  if (agg_ == AggregationLevel::kConnection) {
    auto labels = correlator_->GetLabelKeys();
    for (auto it : labels) {
      descriptor.add_column(opencensus::tags::TagKey::Register(it));
    }
    descriptor.add_column(opencensus::tags::TagKey::Register("local_ip"));
    descriptor.add_column(opencensus::tags::TagKey::Register("remote_ip"));
  }
  descriptor.RegisterForExport();
  return absl::OkStatus();
}

opencensus::tags::TagMap& OCGCPMetricExporter::GetTagMap(const std::string& uuid) {
  if (agg_ == AggregationLevel::kConnection) {
    auto it = tag_maps_.find(uuid);
    if (it != tag_maps_.end()) {
      return *(it->second);
    }

    auto tag_vector = default_tag_vector_;

    size_t pos = uuid.find("->");

    std::string local_ip = uuid.substr(0, pos);
    std::string remote_ip = uuid.substr(pos+2);

    tag_vector.push_back(
        std::make_pair(opencensus::tags::TagKey::Register("local_ip"), local_ip));
    tag_vector.push_back(
        std::make_pair(opencensus::tags::TagKey::Register("remote_ip"), remote_ip));

    auto labels = correlator_->GetLabels(uuid);

    for (auto label : labels) {
      tag_vector.push_back(std::make_pair(
          opencensus::tags::TagKey::Register(label.first), label.second));
    }

    tag_maps_[uuid] = new opencensus::tags::TagMap(tag_vector);
    return *tag_maps_[uuid];
  }
  return *default_tag_map_;
}

static uint64_t GetMs(uint64_t val, MetricTimeType type) {
  switch (type) {
    case MetricTimeType::knsec:
      return val / 1000000;
    case MetricTimeType::kusec:
      return val / 1000;
    case MetricTimeType::kmsec:
      return val;
    case MetricTimeType::ksec:
      return val * 1000;
    case MetricTimeType::kmin:
      return val * 60 * 000;
    case MetricTimeType::khour:
      return val * 3600 * 1000;
  }
  // This will not happen;
  return 0;
}

absl::Status OCGCPMetricExporter::HandleData(std::string metric_name, void* key,
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

  auto ms_it = measures_.find(metric_name);
  if (ms_it == measures_.end()) {
    return absl::NotFoundError("metric measure not found");
  }

  absl::StatusOr<uint64_t> val =
      ExportersUtil::GetMetric(&(metric->data), metric_desc->second.value_type);
  if (!val.ok()) {
    return val.status();
  }

  if (metric_desc->second.unit.type == MetricUnitType::kTime) {
    *val = GetMs(*val, metric_desc->second.unit.time);
  }

  if (metric_desc->second.kind == MetricKind::kCumulative) {
    *val = *val - data_memeory_.StoreAndGetValue(metric_name, *uuid, *val);
  }

  auto tagMap = GetTagMap(*uuid);

  opencensus::stats::Record({{ms_it->second, *val}}, tagMap);

  return absl::OkStatus();
}

absl::Status OCGCPMetricExporter::CustomLabels(
    const absl::flat_hash_map<std::string, std::string>& labels) {
  for (auto& tag : default_tag_vector_) {
    if (labels.find(tag.first.name()) != labels.end()) {
      return absl::AlreadyExistsError(tag.first.name());
    }
  }

  for (auto& label : labels) {
    auto tag = opencensus::tags::TagKey::Register(label.first);
    default_tag_vector_.push_back(std::make_pair(tag, label.second));
  }

  free(default_tag_map_);
  default_tag_map_ = new opencensus::tags::TagMap(default_tag_vector_);
  return absl::OkStatus();
}

void OCGCPMetricExporter::Cleanup() {
  auto uuids = last_read_.GetUUID();
  for (auto uuid : uuids) {
    if (!correlator_->CheckUUID(uuid)) {
      last_read_.DeleteValue(uuid);
      data_memeory_.DeleteValue(uuid);
      tag_maps_.erase(uuid);
    }
  }
}

}  // namespace prober
