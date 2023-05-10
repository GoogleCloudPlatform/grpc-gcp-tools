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

#ifndef _DATA_MANAGER_H_
#define _DATA_MANAGER_H_

#include <stdint.h>

#include <string>
#include <unordered_map>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "event2/event.h"
#include "loader/correlator/correlator.h"
#include "loader/source/data_source.h"

namespace prober {
class DataManager {
 public:
  DataManager() = delete;
  DataManager(struct event_base *base);
  absl::Status Register(DataCtx *ctx);
  void AddExternalLogHandler(LogHandlerInterface *log_handler);
  void AddExternalMetricHandler(MetricHandlerInterface *metric_handler);
  absl::Status AddLogHandler(std::string name,
                             LogHandlerInterface *log_handler);
  absl::Status AddMetricHandler(std::string name,
                                MetricHandlerInterface *metric_handler);

 private:
  struct DataManagerCtx {
    void *this_;
    DataCtx *ctx;
  };
  void ReadMap(const struct DataManagerCtx *d_ctx);
  absl::Status RegisterLog(DataCtx *ctx);
  absl::Status RegisterMetric(DataCtx *ctx);
  static void HandleLostEvents(void *ctx, int cpu, __u64 lost_cnt);
  static void HandlePerf(void *d_ctx, int cpu, void *data, uint32_t data_sz);
  static void HandleEvent(evutil_socket_t, short, void *arg); // NOLINT
  static void HandleCleanup(evutil_socket_t, short, void *arg); // NOLINT

  absl::flat_hash_map<std::string, DataCtx *> data_sources_;
  absl::flat_hash_map<std::string, bool> registered_sources_;
  absl::flat_hash_map<std::string, std::vector<LogHandlerInterface *> >
      log_handlers_;
  absl::flat_hash_map<std::string, std::vector<MetricHandlerInterface *> >
      metric_handlers_;
  std::vector<MetricHandlerInterface *> ext_metric_handlers_;
  std::vector<LogHandlerInterface *> ext_log_handlers_;
  std::vector<struct event *> events_;
  struct event_base *base_;
};

}  // namespace prober

#endif  // _DATA_MANAGER_H_
