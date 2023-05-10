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

#include "data_manager.h"

#include <atomic>
#include <cstddef>
#include <iostream>
#include <ostream>
#include <string>

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/time/time.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "event2/event.h"
#include "loader/exporter/data_types.h"
#include "loader/exporter/log_exporter.h"
#include "loader/exporter/metric_exporter.h"
#include "loader/source/data_source.h"

namespace prober {

#define PERF_PAGES 2

DataManager::DataManager(struct event_base *base) : base_(base) {
  struct event *event = nullptr;
  struct DataManagerCtx *data_ctx = new (struct DataManagerCtx);
  data_ctx->this_ = this;
  data_ctx->ctx = nullptr;
  event = event_new(base_, -1, EV_PERSIST, HandleCleanup, (void *)data_ctx);
  auto timeval = absl::ToTimeval(absl::Seconds(60));
  event_add(event, &timeval);
  events_.push_back(event);
}

absl::Status DataManager::RegisterLog(DataCtx *ctx) {
  struct event *event = nullptr;
  struct DataManagerCtx *data_ctx = new (struct DataManagerCtx);
  data_ctx->this_ = this;
  data_ctx->ctx = ctx;
  event = event_new(base_, -1, EV_PERSIST, DataManager::HandleEvent,
                    (void *)data_ctx);
  ctx->buffer_ =
      perf_buffer__new(ctx->bpf_map_fd_, PERF_PAGES, DataManager::HandlePerf,
                       DataManager::HandleLostEvents, data_ctx, nullptr);
  if (ctx->buffer_ == nullptr) {
    return absl::InternalError(
        absl::StrFormat("Cannot create perf_buffer %s", ctx->name_));
  }

  registered_sources_[ctx->name_] = true;
  auto timeval = absl::ToTimeval(ctx->poll_);
  event_add(event, &timeval);
  events_.push_back(event);
  return absl::OkStatus();
}

absl::Status DataManager::RegisterMetric(DataCtx *ctx) {
  struct event *event = nullptr;
  struct DataManagerCtx *data_ctx = new (struct DataManagerCtx);
  data_ctx->this_ = this;
  data_ctx->ctx = ctx;
  event = event_new(base_, -1, EV_PERSIST, HandleEvent, (void *)data_ctx);
  registered_sources_[ctx->name_] = true;
  auto timeval = absl::ToTimeval(ctx->poll_);
  event_add(event, &timeval);
  events_.push_back(event);
  return absl::OkStatus();
}

absl::Status DataManager::Register(DataCtx *ctx) {
  if (ctx->name_.empty()) {
    return absl::InvalidArgumentError("ctx not initialized");
  }
  if (data_sources_.find(ctx->name_) != data_sources_.end()) {
    if (ctx->shared_) {
      return absl::OkStatus();
    }
    return absl::AlreadyExistsError(ctx->name_);
  }
  data_sources_[ctx->name_] = ctx;
  if (ctx->internal_){
    return absl::OkStatus();
  }
  switch (ctx->type_) {
    case DataCtx::kLog:
      return RegisterLog(ctx);
      
    case DataCtx::kMetric:
      return RegisterMetric(ctx);
 
    case DataCtx::kUninitialized:
    default:
      return absl::InvalidArgumentError("ctx uninitialized");
  }

  return absl::OkStatus();
}

void DataManager::HandleLostEvents(void *ctx, int cpu, __u64 lost_cnt) {
  DataCtx *ptr = (DataCtx *)ctx;
  ptr->lost_events_ += lost_cnt;
}

void DataManager::AddExternalLogHandler(LogHandlerInterface *log_handler) {
  ext_log_handlers_.push_back(log_handler);
}
void DataManager::AddExternalMetricHandler(
    MetricHandlerInterface *metric_handler) {
  ext_metric_handlers_.push_back(metric_handler);
}

absl::Status DataManager::AddLogHandler(std::string name,
                                        LogHandlerInterface *log_handler) {
  if (registered_sources_.find(name) == registered_sources_.end()) {
    auto status = RegisterLog(data_sources_[name]);
    if (!status.ok()) {
      return status;
    }
  }
  log_handlers_[name].push_back(log_handler);
  return absl::OkStatus();
}

absl::Status DataManager::AddMetricHandler(
    std::string name, MetricHandlerInterface *metric_handler) {
  if (registered_sources_.find(name) == registered_sources_.end()) {
    auto status = RegisterMetric(data_sources_[name]);
    if (!status.ok()) {
      return status;
    }
  }
  metric_handlers_[name].push_back(metric_handler);
  return absl::OkStatus();
}

void DataManager::HandlePerf(void *arg, int cpu, void *data, uint32_t data_sz) {
  const struct DataManagerCtx *d_ctx =
      static_cast<const struct DataManagerCtx *>(arg);
  struct DataCtx *ctx = static_cast<DataCtx *>(d_ctx->ctx);
  DataManager *this_ = (DataManager *)d_ctx->this_;

  if (ctx->internal_ == false) {
    for (auto handler : this_->ext_log_handlers_) {
      auto status = handler->HandleData(ctx->name_, data, data_sz);
      if (!status.ok()) {
        std::cout << status << std::endl;
      }
    }
  }

  auto handler_it = this_->log_handlers_.find(ctx->name_);
  if (handler_it != this_->log_handlers_.end()) {
    for (auto handler : handler_it->second) {
      auto status = handler->HandleData(ctx->name_, data, data_sz);
      if (!status.ok()) {
        std::cout << status << std::endl;
      }
    }
  }
}

void DataManager::ReadMap(const struct DataManagerCtx *d_ctx) {
  uint64_t key = 0;
  uint64_t data = 0;
  DataManager *this_ = (DataManager *)d_ctx->this_;
  struct DataCtx *ctx = static_cast<DataCtx *>(d_ctx->ctx);

  int err = bpf_map_get_next_key(ctx->bpf_map_fd_, nullptr, &key);
  if (err) return;
  do {
    bpf_map_lookup_elem(ctx->bpf_map_fd_, (void *)&key, (void *)&data);

    if (ctx->internal_ == false) {
      for (auto handler : this_->ext_metric_handlers_) {
        auto status =
            handler->HandleData(ctx->name_, (void *)&key, (void *)&data);
        if (!status.ok()) {
          std::cout << status << std::endl;
        }
      }
    }
    auto handler_it = this_->metric_handlers_.find(ctx->name_);
    if (handler_it != this_->metric_handlers_.end()) {
      for (auto handler : handler_it->second) {
        auto status =
            handler->HandleData(ctx->name_, (void *)&key, (void *)&data);
        if (!status.ok()) {
          std::cout << status << std::endl;
        }
      }
    }
  } while (bpf_map_get_next_key(ctx->bpf_map_fd_, &key, &key) == 0);
}

void DataManager::HandleEvent(evutil_socket_t, short, void *arg) {  // NOLINT
  struct DataManagerCtx *d_ctx = static_cast<struct DataManagerCtx *>(arg);
  struct DataCtx *ctx = static_cast<DataCtx *>(d_ctx->ctx);
  DataManager *this_ = (DataManager *)d_ctx->this_;
  switch (ctx->type_) {
    case DataCtx::kLog: {
      perf_buffer__consume(ctx->buffer_);
      break;
    }
    case DataCtx::kMetric: {
      this_->ReadMap(d_ctx);
      break;
    }
    default:
      break;
  }
}

void DataManager::HandleCleanup(evutil_socket_t, short, void *arg) {  // NOLINT
  struct DataManagerCtx *d_ctx = static_cast<struct DataManagerCtx *>(arg);
  DataManager *this_ = (DataManager *)d_ctx->this_;
  absl::flat_hash_set<MetricHandlerInterface *> handlers;

  for (auto handler : this_->ext_metric_handlers_) {
    handler->Cleanup();
  }

  for (auto handler_it : this_->metric_handlers_) {
    for (auto handler : handler_it.second) {
      if (handlers.find(handler) != handlers.end()) {
        continue;
      }
      handlers.insert(handler);
      handler->Cleanup();
    }
  }
}

}  // namespace prober
