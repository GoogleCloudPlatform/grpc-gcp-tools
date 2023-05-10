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

#ifndef _LOADER_SOURCE_DATA_SOURCE_H_
#define _LOADER_SOURCE_DATA_SOURCE_H_

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "bpf/libbpf.h"
#include "loader/exporter/data_types.h"
#include "loader/source/probes.h"

namespace prober {

class DataCtx {
 public:
  enum SourceType {
    kUninitialized,
    kLog,
    kMetric,
  };
  DataCtx() = default;
  DataCtx(std::string name, LogDesc log_desc, absl::Duration poll,
          bool internal, bool shared)
      : type_(kLog),
        name_(name),
        log_desc_(log_desc),
        poll_(poll),
        internal_(internal),
        shared_(shared) {}
  DataCtx(std::string name, MetricDesc metric_desc, absl::Duration poll,
          bool internal, bool shared)
      : type_(kMetric),
        name_(name),
        metric_desc_(metric_desc),
        poll_(poll),
        internal_(internal),
        shared_(shared) {}
  SourceType type_;
  std::string name_;
  union {
    MetricDesc metric_desc_;
    LogDesc log_desc_;
  };
  absl::Duration poll_;
  bpf_map *map_;
  int bpf_map_fd_;
  struct perf_buffer *buffer_;
  bool internal_;
  bool shared_;
  uint32_t lost_events_;
};

class DataSource {
 public:
  DataSource() = default;
  DataSource(std::vector<Probe *> probes, std::vector<DataCtx *> log_sources,
             std::vector<DataCtx *> metric_sources, const char *file_name,
             const char *file_name_core, const char *pid_filter_map);
  virtual absl::Status Init();
  virtual absl::Status LoadObj();
  // When overloading this method make sure to use map_memory for fds of shared
  virtual absl::Status LoadMaps();
  virtual absl::Status LoadProbes();
  virtual std::vector<DataCtx *> &GetLogSources();
  virtual std::vector<DataCtx *> &GetMetricSources();
  virtual absl::Status AttachProbe(std::string probe_name);
  virtual absl::Status DetachProbe(std::string probe_name);
  virtual absl::StatusOr<DataCtx *> GetMap(std::string map_name);
  virtual absl::Status FilterPID(pid_t pid);
  virtual std::string ToString() const { return "DataSource"; };
  virtual ~DataSource() = default;

 protected:
  std::string file_name_;
  std::string file_name_core_;
  struct bpf_object *obj_;
  std::vector<Probe *> probes_;
  std::vector<DataCtx *> log_sources_;
  std::vector<DataCtx *> metric_sources_;
  std::string pid_filter_map_;
  void Cleanup();
  bool init_;

 private:
  absl::Status ShareMaps();
};

}  // namespace prober

#endif  // _LOADER_SOURCE_DATA_SOURCE_H_
