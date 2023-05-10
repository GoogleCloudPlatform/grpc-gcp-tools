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

#ifndef _LOADER_SOURCE_PROBES_H_
#define _LOADER_SOURCE_PROBES_H_
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "bpf/libbpf.h"

namespace prober {

class Probe {
 public:
  std::string name_;
  struct bpf_program *prog_;
  struct bpf_link *link_;
  int prog_fd_;

  explicit Probe(std::string name)
      : name_(name), prog_(nullptr), link_(nullptr) {}

  void SetProg(bpf_program *prog) { prog_ = prog; }

  virtual absl::Status Attach() {
    if (prog_ == nullptr) return absl::NotFoundError("Prog not set");
    link_ = bpf_program__attach(prog_);
    if (link_ == nullptr) return absl::InternalError("Attach failed");
    prog_fd_ = bpf_link__fd(link_);
    if (prog_fd_ < 0) {
      return absl::InternalError("Link file descriptor not found");
    }
    return absl::OkStatus();
  }

  virtual absl::Status Detach() {
    if (link_ == nullptr) return absl::OkStatus();
    auto err = bpf_link__detach(link_);
    if (err) {
      char errBuffer[50] = {0};
      libbpf_strerror(err, errBuffer, sizeof(errBuffer));
      return absl::InternalError(
          absl::StrFormat("Detach Failed %s", errBuffer));
    }
    return absl::OkStatus();
  }

  virtual ~Probe() {
    if (link_ == nullptr) return;
    bpf_link__destroy(link_);
    link_ = nullptr;
  }
};

class RawTPProbe : public Probe {
  std::string probe_cat_;
  std::string probe_fn_;

 public:
  RawTPProbe(std::string name, std::string probe_cat, std::string probe_fn)
      : Probe(name), probe_cat_(probe_cat), probe_fn_(probe_fn) {}
  absl::Status Attach() override {
    // struct stat sb;
    // std::string path =
    //       absl::StrFormat("/sys/kernel/debug/tracing/events/%s/%s/enable",
    //             probe_cat_, probe_fn_);
    // if (lstat(path.c_str(), &sb) == -1) {
    //    return absl::UnimplementedError(
    //        absl::StrFormat("Tracepoint %s not implemented", path));
    // }

    if (prog_ == nullptr) return absl::NotFoundError("Prog not set");
    link_ = bpf_program__attach_raw_tracepoint(prog_, probe_fn_.c_str());
    if (link_ == nullptr) {
      return absl::InternalError("Attach failed");
    }
    prog_fd_ = bpf_link__fd(link_);
    if (prog_fd_ < 0) {
      return absl::InternalError("Link file descriptor not found");
    }
    return absl::OkStatus();
  }
};

class UProbe : public Probe {
  std::string binary_name_;
  uint64_t func_offset_;
  bool retprobe_;
  pid_t pid_;

 public:
  UProbe(std::string name, std::string binary_name, uint64_t func_offset,
         bool retprobe, pid_t pid)
      : Probe(name),
        binary_name_(binary_name),
        func_offset_(func_offset),
        retprobe_(retprobe),
        pid_(pid) {}
  absl::Status Attach() override {
    if (prog_ == nullptr) return absl::NotFoundError("Prog not set");
    link_ = bpf_program__attach_uprobe(prog_, retprobe_, pid_,
                                       binary_name_.c_str(), func_offset_);
    if (link_ == nullptr) {
      return absl::InternalError("Attach failed");
    }
    prog_fd_ = bpf_link__fd(link_);
    if (prog_fd_ < 0) {
      return absl::InternalError("Link file descriptor not found");
    }
    return absl::OkStatus();
  }
};

class KProbe : public Probe {
  std::string function_name_;
  bool retprobe_;

 public:
  KProbe(std::string name, std::string function_name, bool retprobe)
      : Probe(name), function_name_(function_name), retprobe_(retprobe) {}
  absl::Status Attach() override {
    if (prog_ == nullptr) return absl::NotFoundError("Prog not set");
    link_ =
        bpf_program__attach_kprobe(prog_, retprobe_, function_name_.c_str());
    if (link_ == nullptr) {
      return absl::InternalError("Attach failed");
    }
    prog_fd_ = bpf_link__fd(link_);
    if (prog_fd_ < 0) {
      return absl::InternalError("Link file descriptor not found");
    }
    return absl::OkStatus();
  }
};
}  // namespace prober

#endif  // _LOADER_SOURCE_PROBES_H_
