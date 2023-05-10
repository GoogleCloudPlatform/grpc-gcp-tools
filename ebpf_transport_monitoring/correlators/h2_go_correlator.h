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

#ifndef _CORRELATORS_H2_GO_CORRELATOR_
#define _CORRELATORS_H2_GO_CORRELATOR_

#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "event2/event.h"
#include "loader/correlator/correlator.h"

namespace prober {

class H2GoCorrelator : public CorrelatorInterface {
 public:
  H2GoCorrelator() = default;
  ~H2GoCorrelator() = default;
  absl::Status Init() override;

  std::vector<DataCtx*>& GetLogSources();
  std::vector<DataCtx*>& GetMetricSources();
  absl::flat_hash_map<std::string, std::string> GetLabels(
      std::string uuid) override;
  std::vector<std::string> GetLabelKeys() override;

 private:
  struct ConnInfo {
    uint64_t pid;
    uint64_t h2_conn_id;
    uint64_t tcp_conn_id;
    std::string UUID;
  };
  absl::Status HandleData(std::string log_name, const void* const data,
                          const uint32_t size) override;
  absl::Status HandleData(std::string metric_name, void* key,
                          void* value) override;
  bool CheckUUID(std::string uuid) override;
  void Cleanup() override{};

  absl::Status HandleTCP(const void* const data);
  absl::Status HandleHTTP2(const void* const data);
  absl::Status HandleHTTP2Events(const void* const data);

  std::vector<DataCtx*> log_sources_;
  std::vector<DataCtx*> metric_sources_;

  absl::flat_hash_map<std::string, struct ConnInfo> correlator_;
};

}  // namespace prober

#endif
