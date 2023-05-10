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

#include "sources/source_manager/h2_go_grpc_source.h"

#include <cmath>
#include <cstddef>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "loader/source/data_source.h"
#include "loader/source/dwarf_reader.h"
#include "loader/source/probes.h"
#include "loader/source/proc_reader.h"
#include "loader/source/sym_addrs.h"
#include "re2/re2.h"
#include "sources/common/defines.h"
#include "sources/common/h2_symaddrs.h"
#include "sources/common/sym_types.h"

namespace prober {

// File name is hardcoded with a relative location for now.
// Will do something better later.
H2GoGrpcSource::H2GoGrpcSource()
    : DataSource::DataSource(
          {},
          {new DataCtx("h2_grpc_events", LogDesc{}, absl::Seconds(2), false, true),
           new DataCtx("h2_grpc_correlation", LogDesc{}, absl::Seconds(2),
                       true, false)},
          {
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
              {new DataCtx("h2_grpc_pid_filter",
                           MetricDesc{MetricType::kUint64,
                                      MetricType::kUint64,
                                      MetricKind::kNone,
                                      {MetricUnitType::kNone}},
                           absl::Seconds(60), true, false)},
              {new DataCtx("h2_connection",
                           MetricDesc{MetricType::kUint64,
                                      MetricType::kInternal,
                                      MetricKind::kNone,
                                      {MetricUnitType::kNone}},
                           absl::Seconds(60), true, true)},
          },
          "./h2_bpf.o", "./h2_bpf_core.o", "h2_grpc_pid_filter") {}

static void InitCfg(h2_cfg_t* bpf_cfg) {
  bpf_cfg->variables = {
      .connection = {.type = kLocationTypeRegisters, .offset = 0},
      .frame = {.type = kLocationTypeRegisters, .offset = 1},
      .buf_writer = {.type = kLocationTypeRegisters, .offset = 0},
      .write_buffer_len = {.type = kLocationTypeRegisters, .offset = 2},
      .write_buffer_ptr = {.type = kLocationTypeRegisters, .offset = 1},
  };
}

absl::Status GetValue(prober::DwarfReader& reader, std::string struct_name,
                      std::string member_name, member_var_t* member,
                      int32_t size) {
  auto mem = reader.GetMemberVar(struct_name, member_name);
  if (!mem.ok()) {
    return mem.status();
  }
  *member = *mem;
  if (member->size == -1) {
    member->size = size;
  }
  return absl::OkStatus();
}

static absl::Status GetStructOffsets(std::string& path, h2_cfg_t* bpf_cfg) {
  absl::flat_hash_map<std::string, absl::flat_hash_set<std::string> > structs;

  structs["http2.FrameHeader"] = {
      {"Type"}, {"Flags"}, {"Length"}, {"StreamID"}};

  structs["http2.DataFrame"] = {{"data"}};

  structs["http2.RSTStreamFrame"] = {{"ErrCode"}};

  structs["http2.SettingsFrame"] = {{"p"}};

  structs["http2.GoAwayFrame"] = {{"ErrCode"}, {"LastStreamID"}};

  structs["transport.http2Client"] = {
      {"framer"}, {"localAddr"}, {"remoteAddr"}};

  structs["transport.http2Server"] = {
      {"framer"}, {"localAddr"}, {"remoteAddr"}};

  structs["transport.framer"] = {
      {"writer"},
  };

  structs["net.TCPAddr"] = {{"IP"}, {"Port"}};

  prober::DwarfReader reader(path);

  absl::Status status = reader.FindStructs(structs);
  if (!status.ok()) {
    // use default values
    bpf_cfg->offset = {
        .frameheader_type = {.offset = 1, .size = 1},
        .frameheader_flags = {.offset = 2, .size = 1},
        .frameheader_length = {.offset = 4, .size = 4},
        .frameheader_streamid = {.offset = 8, .size = 4},
        .dataframe_data = {.offset = 16, .size = sizeof(struct go_slice)},
        .rstframe_error = {.offset = 12, .size = 4},
        .goawayframe_error = {.offset = 16, .size = 4},
        .goawayframe_stream = {.offset = 12, .size = 4},
        .settingsframe_data = {.offset = 16, .size = sizeof(struct go_slice)},
        .client_framer = {.offset = 160, .size = sizeof(uint64_t)},
        .server_framer = {.offset = 128, .size = sizeof(uint64_t)},
        .framer_bufwriter = {.offset = 0, .size = sizeof(uint64_t)},
        .client_laddr = {.offset = 104, .size = sizeof(struct go_interface)},
        .client_raddr = {.offset = 88, .size = sizeof(struct go_interface)},
        .server_laddr = {.offset = 88, .size = sizeof(struct go_interface)},
        .server_raddr = {.offset = 72, .size = sizeof(struct go_interface)},
        .tcp_ip = {.offset = 0, .size = 16},
        .tcp_port = {.offset = 24, .size = 8}};
  } else {
#define CHECK_STATUS(status) \
  if (!status.ok()) {        \
    return status;           \
  }
    CHECK_STATUS(GetValue(reader, "http2.FrameHeader", "Type",
                          &bpf_cfg->offset.frameheader_type, 1));
    CHECK_STATUS(GetValue(reader, "http2.FrameHeader", "Flags",
                          &bpf_cfg->offset.frameheader_flags, 1));
    CHECK_STATUS(GetValue(reader, "http2.FrameHeader", "Length",
                          &bpf_cfg->offset.frameheader_length, 4));
    CHECK_STATUS(GetValue(reader, "http2.FrameHeader", "StreamID",
                          &bpf_cfg->offset.frameheader_streamid, 4));
    CHECK_STATUS(GetValue(reader, "http2.DataFrame", "data",
                          &bpf_cfg->offset.dataframe_data,
                          sizeof(struct go_slice)));
    CHECK_STATUS(GetValue(reader, "http2.RSTStreamFrame", "ErrCode",
                          &bpf_cfg->offset.rstframe_error, -1));
    CHECK_STATUS(GetValue(reader, "transport.http2Client", "framer",
                          &bpf_cfg->offset.client_framer, sizeof(uint64_t)));
    CHECK_STATUS(GetValue(reader, "transport.http2Client", "localAddr",
                          &bpf_cfg->offset.client_laddr,
                          sizeof(struct go_interface)));
    CHECK_STATUS(GetValue(reader, "transport.http2Client", "remoteAddr",
                          &bpf_cfg->offset.client_raddr,
                          sizeof(struct go_interface)));
    CHECK_STATUS(GetValue(reader, "transport.http2Server", "localAddr",
                          &bpf_cfg->offset.server_laddr,
                          sizeof(struct go_interface)));
    CHECK_STATUS(GetValue(reader, "transport.http2Server", "remoteAddr",
                          &bpf_cfg->offset.server_raddr,
                          sizeof(struct go_interface)));
    CHECK_STATUS(GetValue(reader, "transport.http2Server", "framer",
                          &bpf_cfg->offset.server_framer, sizeof(uint64_t)));
    CHECK_STATUS(GetValue(reader, "transport.framer", "writer",
                          &bpf_cfg->offset.framer_bufwriter, sizeof(uint64_t)));
    CHECK_STATUS(GetValue(reader, "http2.SettingsFrame", "p",
                          &bpf_cfg->offset.settingsframe_data, -1));
    CHECK_STATUS(GetValue(reader, "http2.GoAwayFrame", "ErrCode",
                          &bpf_cfg->offset.goawayframe_error, -1));
    CHECK_STATUS(GetValue(reader, "http2.GoAwayFrame", "LastStreamID",
                          &bpf_cfg->offset.goawayframe_stream, -1));
    CHECK_STATUS(GetValue(reader, "net.TCPAddr", "IP", &bpf_cfg->offset.tcp_ip,
                          sizeof(struct go_slice)));
    CHECK_STATUS(GetValue(reader, "net.TCPAddr", "Port",
                          &bpf_cfg->offset.tcp_port, sizeof(uint64_t)));
#undef CHECK_STATUS
  }

  return absl::OkStatus();
}

static absl::Status GetTypes(ElfReader* elf_reader, h2_cfg_t* bpf_cfg) {
  absl::flat_hash_map<std::string, uint64_t> symbols = {
      {"go:itab.*net.TCPAddr,net.Addr", 0},
      {"go.itab.*net.TCPAddr,net.Addr", 0}};
  auto status = elf_reader->GetSymbols(symbols, ElfReader::kValue);
  if (!status.ok()) {
    return status;
  }
#define GET_VALUE(sym1, sym2, value)                              \
  if (symbols[sym1] != 0) {                                       \
    value = symbols[sym1];                                        \
  } else if (symbols[sym2] != 0) {                                \
    value = symbols[sym2];                                        \
  } else {                                                        \
    return absl::NotFoundError(                                   \
        absl::StrFormat("Type %s and %s not found", sym1, sym2)); \
  }

  GET_VALUE("go:itab.*net.TCPAddr,net.Addr", "go.itab.*net.TCPAddr,net.Addr",
            bpf_cfg->types.tcp_addr);
#undef GET_VALUE

  return absl::OkStatus();
}

absl::Status H2GoGrpcSource::CreateProbes(
    ElfReader* elf_reader, uint64_t pid, std::string& path,
    absl::flat_hash_map<std::string, uint64_t>& functions,
    const char* probe_func) {
  auto status = elf_reader->GetSymbols(functions, ElfReader::kOffset);

  if (!status.ok()) {
    return status;
  }

  int count = 0;
  for (auto it = functions.begin(); it != functions.end(); ++it) {
    if (it->second == 0) {
      continue;
    }
    count++;
    probes_.push_back(new UProbe(probe_func, path, it->second, false, pid));
  }

  if (count == 0) {
    return absl::InternalError("Could not find any address.");
  }

  return absl::OkStatus();
}

static absl::Status GetGolangVersion(ElfReader* elf_reader, int* major_version,
                                     int* minor_version) {
  absl::flat_hash_map<std::string, uint64_t> functions;

  functions["runtime.buildVersion"] = 0;
  absl::Status status = elf_reader->GetSymbols(functions, ElfReader::kOffset);
  if (!status.ok()) {
    return status;
  }

  if (functions["runtime.buildVersion"] == 0) {
    return absl::InternalError("Could not find go version");
  }
  char* buffer = (char*)calloc(10, sizeof(char));
  status = elf_reader->ReadData(nullptr, functions["runtime.buildVersion"],
                                buffer, sizeof(struct go_string));
  struct go_string* str = (struct go_string*)buffer;
  if (!status.ok()) {
    goto cleanup;
  }

  status = elf_reader->ReadData(".rodata", (uint64_t)str->ptr, buffer, 10);
  if (!status.ok()) {
    goto cleanup;
  }

  if (!RE2::PartialMatch(buffer, "go(\\d+).(\\d+)", major_version,
                         minor_version)) {
    status = absl::InternalError(
        absl::StrCat("Could not regex match go version", buffer));
    goto cleanup;
  }
cleanup:
  free(buffer);
  return status;
}

absl::Status H2GoGrpcSource::RegisterProbes(ElfReader* elf_reader,
                                            std::string& path, uint64_t pid) {
  /* The unimportant functions are commented.*/
  absl::flat_hash_map<std::string, uint64_t> client_functions{
      {"transport.(*http2Client).handleData", 0},
      {""
       "transport.(*http2Client).handleRSTStream",
       0},
      // {""
      //  "transport.(*http2Client).handleSettings",
      //  0},
      // {"transport.(*http2Client).handlePing",
      //  0},
      {"transport.(*http2Client).handleGoAway", 0},
      // {""
      //  "transport.(*http2Client).handleWindowUpdate",
      //  0}
  };
  auto status = CreateProbes(elf_reader, pid, path, client_functions,
                             "probe_handle_client_data");
  if (!status.ok()) return status;

  absl::flat_hash_map<std::string, uint64_t> server_functions{
      {"transport.(*http2Server).handleData", 0},
      {""
       "transport.(*http2Server).handleRSTStream",
       0},
      // {""
      //  "transport.(*http2Server).handleSettings",
      //  0},
      // {"transport.(*http2Server).handlePing",
      //  0},
      // {""
      //  "transport.(*http2Server).handleWindowUpdate",
      //  0}
  };

  status = CreateProbes(elf_reader, pid, path, server_functions,
                        "probe_handle_server_data");
  if (!status.ok()) return status;

  absl::flat_hash_map<std::string, uint64_t> server_header_functions{
      {""
       "transport.(*http2Server).operateHeaders",
       0}};

  status = CreateProbes(elf_reader, pid, path, server_header_functions,
                        "probe_handle_server_header");
  if (!status.ok()) return status;

  absl::flat_hash_map<std::string, uint64_t> client_header_functions{
      {""
       "transport.(*http2Client).operateHeaders",
       0}};

  status = CreateProbes(elf_reader, pid, path, client_header_functions,
                        "probe_handle_client_header");
  if (!status.ok()) return status;

  absl::flat_hash_map<std::string, uint64_t> buf_writer_functions{
      {"transport.(*bufWriter).Write", 0}};

  status = CreateProbes(elf_reader, pid, path, buf_writer_functions,
                        "probe_sent_frame");
  if (!status.ok()) return status;

  absl::flat_hash_map<std::string, uint64_t> close_functions{
      {"transport.(*http2Client).Close", 0},
      {"transport.(*http2Server).Close", 0}};

  return CreateProbes(elf_reader, pid, path, close_functions, "probe_close");
}

absl::Status H2GoGrpcSource::AddPID(uint64_t pid) {
  int major_version, minor_version;

  if (bpf_cfg_.find(pid) != bpf_cfg_.end()) {
    return absl::AlreadyExistsError(absl::StrFormat("Pid %d"));
  }

  auto path = ProcReader::GetBinaryPath(pid);
  if (!path.ok()) {
    return path.status();
  }

  std::cout << "Path:" << *path << std::endl;

  ElfReader elf_reader(*path);

  absl::Status status =
      GetGolangVersion(&elf_reader, &major_version, &minor_version);
  if (!status.ok()) {
    return status;
  }

  if (major_version >= 1 && minor_version > 16) {
    // use register based config
  } else {
    absl::PrintF("Golang Version %d %d", major_version, minor_version);
    return absl::UnimplementedError("Stack based reg not tested yet.");
  }

  h2_cfg_t bpf_cfg;

  InitCfg(&bpf_cfg);
  status = GetStructOffsets(*path, &bpf_cfg);
  if (!status.ok()) {
    return status;
  }

  status = GetTypes(&elf_reader, &bpf_cfg);
  if (!status.ok()) {
    return status;
  }

  status = RegisterProbes(&elf_reader, *path, pid);
  if (!status.ok()) {
    return status;
  }

  bpf_cfg_[pid] = bpf_cfg;

  return absl::OkStatus();
}

absl::Status H2GoGrpcSource::LoadMaps() {
  absl::Status status = DataSource::LoadMaps();
  if (!status.ok()) {
    return status;
  }
  auto map = bpf_object__find_map_by_name(obj_, "h2_cfg");
  if (map == nullptr) {
    return absl::NotFoundError("Could not find config map");
  }

  for (auto& bpf_cfg_it : bpf_cfg_) {
    int upd_status =
        bpf_map__update_elem(map, &bpf_cfg_it.first, sizeof(uint64_t),
                             &bpf_cfg_it.second, sizeof(h2_cfg_t), BPF_ANY);
    if (upd_status != 0) {
      return absl::InternalError(
          absl::StrFormat("Could not set inital value for map %d: %d",
                          bpf_map__type(map), upd_status));
    }
  }
  return absl::OkStatus();
}

H2GoGrpcSource::~H2GoGrpcSource() { Cleanup(); }

}  // namespace prober
