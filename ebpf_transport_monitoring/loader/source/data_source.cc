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

#include "loader/source/data_source.h"

#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "loader/exporter/data_types.h"
#include "loader/source/probes.h"
#include "loader/source/map_memory.h"
#include "loader/source/source_helper.h"
#include "loader/source/os_helper.h"
#include "loader/source/archive_handler.h"

extern unsigned char _binary_reduced_btfs_tar_gz_start[] __attribute__((weak));
extern unsigned char _binary_reduced_btfs_tar_gz_end[] __attribute__((weak));

namespace prober {

static absl::StatusOr<std::string> GetBtfFilePath(){
    prober::OsHelper helper;
    std::string write_path = "/tmp/lightfoot.reduced.bpf";
    auto status = helper.CaptureOsInfo();
    if (!status.ok()){
      return status;
    }
    auto path = helper.GetBtfArchivePath();
    if (!path.ok()) return path.status();

    if (!_binary_reduced_btfs_tar_gz_start) {
      return absl::InternalError("Reduced binary not linked");
    }

    prober::ArchiveHandler handler(_binary_reduced_btfs_tar_gz_start,
    _binary_reduced_btfs_tar_gz_end - _binary_reduced_btfs_tar_gz_start);

    status = handler.Init();
    if (!status.ok()) return status;

    status = handler.WriteFileToDisk("./debian/10/x86_64/4.19.0-17-amd64.btf",write_path);
    if (!status.ok()) return status;

    if (access(write_path.c_str(), R_OK)){
      return absl::InternalError("Writing reduced btf file failed");
    }
    return write_path;
}

DataSource::DataSource(std::vector<Probe*> probes,
                       std::vector<DataCtx*> log_sources,
                       std::vector<DataCtx*> metric_sources,
                       const char* file_name, const char* file_name_core,
                       const char* pid_filter_map)
    : file_name_(file_name),
      file_name_core_(file_name_core),
      probes_(std::move(probes)),
      log_sources_(std::move(log_sources)),
      metric_sources_(std::move(metric_sources)),
      pid_filter_map_(pid_filter_map),
      init_(false) {}

absl::Status DataSource::Init() {
  struct bpf_object_open_opts open_opts;
  memset(&open_opts, 0, sizeof(struct bpf_object_open_opts));
  open_opts.sz = sizeof(struct bpf_object_open_opts);

  bool core = true;
  if (!SourceHelper::VmlinuxExists()){
    auto path = GetBtfFilePath();
    if (path.ok()){
      open_opts.btf_custom_path = strdup(path->c_str());
    } else {
      core = false;
    }
  }

  if (!core) {
    // This means that this is non-core code.
    std::cout << "Loading " << file_name_ << std::endl;
    obj_ = bpf_object__open_file(file_name_.c_str(), &open_opts);
  } else {
    std::cout << "Loading " << file_name_core_ << std::endl;
    obj_ = bpf_object__open_file(file_name_core_.c_str(), &open_opts);
    if (obj_ == nullptr) {
      std::cout << "Loading " << file_name_ << std::endl;
      obj_ = bpf_object__open_file(file_name_.c_str(), &open_opts);
    }
  }

  if (obj_ == nullptr) {
    return absl::NotFoundError("'BPF object not found");
  }

  auto version = SourceHelper::GetKernelVersion();

  if (version.ok()){
    bpf_object__set_kversion(obj_, *version);
  } else {
    //This is not a fatal error in some cases hence warn.
    std::cerr << "Warn: " << version.status() << std::endl;
  }
  
  return absl::OkStatus();
}


absl::Status DataSource::ShareMaps(){
  struct bpf_map * map;
  bpf_object__for_each_map(map,obj_) {
    const char * name = bpf_map__name(map);
    if (name == nullptr) {
      continue;
    }
    auto map_fd = MapMemory::GetInstance().GetMap(name);
    if (map_fd.ok()){
      int fd = bpf_map__reuse_fd(map, *map_fd);
      if (fd < 0){
        return absl::InternalError(absl::StrFormat("Could not reuse fd %d for map %s", *map_fd, name));
      }
    }
  }
  return absl::OkStatus();
}

absl::Status DataSource::LoadObj() {
  char errBuffer[50] = {0};
  absl::Status status;
  
  status = ShareMaps();
  if (!status.ok()){
    return status;
  }

  auto err = bpf_object__load(obj_);
  if (err) {
    libbpf_strerror(err, errBuffer, sizeof(errBuffer));
    return absl::InternalError("Object load error:" + std::string(errBuffer));
  }

  return absl::OkStatus();
}

absl::Status DataSource::LoadProbes() {
  absl::Status status;
  for (auto& probe : probes_) {
    auto prog = bpf_object__find_program_by_name(obj_, probe->name_.c_str());
    if (prog == nullptr) {
      status = absl::NotFoundError("Probe " + probe->name_ + " not found");
      goto cleanup;
    }
    probe->SetProg(prog);
    status = probe->Attach();
    if (!status.ok()) {
      goto cleanup;
    }
  }
  return absl::OkStatus();
cleanup:
  Cleanup();
  return status;
}

static absl::Status LoadMap(struct bpf_object *obj, struct DataCtx * ctx){
  auto* map = bpf_object__find_map_by_name(obj, ctx->name_.c_str());
  if (map == nullptr) {
    return absl::NotFoundError("Map " + ctx->name_ + " not found");
  }
  ctx->map_ = map;
  ctx->bpf_map_fd_ = bpf_map__fd(map);
  return absl::OkStatus();
}

absl::Status DataSource::LoadMaps() {
  absl::Status status;

  for (auto& ctx : metric_sources_) {
    status = LoadMap(obj_,ctx);
    if (!status.ok()){
      goto cleanup;
    }
  }

  for (auto& ctx : log_sources_) {
    status = LoadMap(obj_,ctx);
    if (!status.ok()){
      goto cleanup;
    } 
  }

  init_ = true;
  return absl::OkStatus();
cleanup:
  Cleanup();
  return status;
}

std::vector<DataCtx*>& DataSource::GetLogSources() { return log_sources_; }

std::vector<DataCtx*>& DataSource::GetMetricSources() {
  return metric_sources_;
}

void DataSource::Cleanup() {
  if (init_ == false) {
    return;
  }

  for (auto& probe : probes_) {
    auto status = probe->Detach();
    if (!status.ok()) {
      std::cerr << status << std::endl;
    }
  }
  if (obj_) bpf_object__close(obj_);
}

absl::Status DataSource::FilterPID(pid_t pid) {
  if (init_ == false) {
    return absl::InternalError("Uninitialized");
  }

  auto map_ctx = GetMap(pid_filter_map_);
  if (!map_ctx.ok()) {
    return map_ctx.status();
  }

  uint8_t value = 1;
  int err = bpf_map_update_elem((*map_ctx)->bpf_map_fd_, (void*)&pid,
                                (void*)&value, BPF_ANY);

  if (err != 0) {
    return absl::InternalError("Error added PID to filter map");
  }
  return absl::OkStatus();
}

absl::Status DataSource::AttachProbe(std::string probe_name) {
  std::vector<Probe*>::iterator it;
  for (it = probes_.begin(); it != probes_.end(); it++) {
    if ((*it)->name_.compare(probe_name) == 0) {
      break;
    }
  }

  if (it == probes_.end()) {
    return absl::NotFoundError(
        absl::StrFormat("Probe %s not found", probe_name));
  }

  return (*it)->Attach();
}

absl::Status DataSource::DetachProbe(std::string probe_name) {
  std::vector<Probe*>::iterator it;
  for (it = probes_.begin(); it != probes_.end(); it++) {
    if ((*it)->name_.compare(probe_name) == 0) {
      break;
    }
  }
  if (it == probes_.end()) {
    return absl::NotFoundError(
        absl::StrFormat("Probe %s not found", probe_name));
  }

  return (*it)->Detach();
}

absl::StatusOr<DataCtx*> DataSource::GetMap(std::string map_name) {
  for (auto& source : metric_sources_) {
    if (!source->name_.compare(map_name)) {
      return source;
    }
  }
  for (auto& source : log_sources_) {
    if (!source->name_.compare(map_name)) {
      return source;
    }
  }
  return absl::NotFoundError(absl::StrFormat("map %s not found", map_name));
}

}  // namespace prober
