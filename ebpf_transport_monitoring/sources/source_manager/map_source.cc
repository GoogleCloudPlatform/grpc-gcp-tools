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

#include "sources/source_manager/map_source.h"

#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

#include "loader/source/data_source.h"
#include "loader/source/map_memory.h"

namespace prober {

// File name is hardcoded with a relative location for now.
// Will do something better later.
MapSource::MapSource() {
  log_sources_ = {
      new DataCtx("h2_grpc_events", LogDesc{}, absl::Seconds(2), false, true)};
  metric_sources_ = {
      {new DataCtx("h2_stream_count",
                    MetricDesc{MetricType::kUint64,
                              MetricType::kUint64,
                              MetricKind::kCumulative,
                              {MetricUnitType::kNone}},
                    absl::Seconds(60), false, true)},
      {new DataCtx("h2_reset_stream_count",
                    MetricDesc{MetricType::kUint64,
                              MetricType::kUint64,
                              MetricKind::kCumulative,
                              {MetricUnitType::kNone}},
                    absl::Seconds(60), false, true)},
      {new DataCtx("h2_ping_counter",
                    MetricDesc{MetricType::kUint64,
                              MetricType::kUint64,
                              MetricKind::kCumulative,
                              {MetricUnitType::kNone}},
                    absl::Seconds(60), true, true)},
      {new DataCtx("h2_stream_id",
                    MetricDesc{MetricType::kUint64,
                              MetricType::kUint64,
                              MetricKind::kNone,
                              {MetricUnitType::kNone}},
                    absl::Seconds(60), true, true)},
      {new DataCtx("h2_connection",
                    MetricDesc{MetricType::kUint64,
                              MetricType::kInternal,
                              MetricKind::kNone,
                              {MetricUnitType::kNone}},
                    absl::Seconds(60), true, true)},
      {new DataCtx("h2_event_heap",
              MetricDesc{MetricType::kUint64,
                        MetricType::kInternal,
                        MetricKind::kNone,
                        {MetricUnitType::kNone}},
              absl::Seconds(60), true, true)}
  };

  file_name_ = "./maps_bpf.o";
  file_name_core_ = "./maps_core.o";
}

absl::Status MapSource::LoadMaps() {
  absl::Status status = DataSource::LoadMaps();
  
  //All Maps are shared.
  const struct bpf_map * map;

  bpf_object__for_each_map(map,obj_) {
    const char * name = bpf_map__name(map);
    int fd = bpf_map__fd(map);
    if (fd < 0){
      return absl::InternalError(absl::StrFormat("Could not get fd  map %s", name));
    }
    auto map_fd = MapMemory::GetInstance().SetMap(name, fd);
  }
  return absl::OkStatus();
}

MapSource::~MapSource() { DataSource::Cleanup(); }

}  // namespace prober
