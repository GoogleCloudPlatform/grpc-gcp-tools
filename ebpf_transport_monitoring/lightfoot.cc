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

#include <event2/event.h>
#include <tclap/CmdLine.h>

#include <cstdint>
#include <iostream>
#include <ostream>
#include <vector>

#include "correlators/h2_go_correlator.h"
#include "data_manager.h"
#include "exporters/file_exporter.h"
#include "exporters/gcp_exporter.h"
#include "exporters/oc_gcp_exporter.h"
#include "exporters/stdout_event_logger.h"
#include "exporters/stdout_metric_exporter.h"
#include "loader/correlator/correlator.h"
#include "loader/exporter/log_exporter.h"
#include "loader/exporter/metric_exporter.h"
#include "loader/source/data_source.h"
#include "sources/source_manager/h2_go_grpc_source.h"
#include "sources/source_manager/tcp_source.h"
#include "sources/source_manager/map_source.h"

#include "absl/status/status.h"

int main(int argc, char **argv) {
  prober::TcpSource tcp_source;
  struct event_base *base = event_base_new();
  prober::DataManager data_manager(base);
  prober::LogExporterInterface *logger;
  prober::MetricExporterInterface *metric_exporter;
  prober::H2GoCorrelator correlator;
  absl::Status status;
  bool file_logging;
  bool host_agg;

  bool gcp_logging, oc_gcp_logging;
  std::string gcp_creds;
  std::string gcp_project;

  std::vector<pid_t> pids;
  std::vector<std::string> custom_labels;

  try {
    TCLAP::CmdLine cmd("eBPF gRPC golang h2 and tcp tracer", ' ', "0.1");
    TCLAP::SwitchArg file_log_switch("f", "file", "Log to file", cmd, false);
    TCLAP::SwitchArg host_agg_switch("s", "host_level",
                                     "Aggregate at host level", cmd, false);
    TCLAP::SwitchArg gcp_log_switch(
        "g", "gcp", "(Deprecated Please use -o) Use stackdriver to export.",
        cmd, false);
    TCLAP::SwitchArg oc_gcp_log_switch(
        "o", "oc_gcp", "Use opencensus stackdriver to export", cmd, false);
    TCLAP::ValueArg<std::string> gcp_creds_cmd("c", "gcp_json_creds",
                                               "File path to read", false, "",
                                               "service acoount credentials");
    TCLAP::ValueArg<std::string> gcp_project_cmd("p", "gcp_Project",
                                                 "GCP metrics to export data",
                                                 false, "", "Project id");
    TCLAP::MultiArg<std::string> custom_labels_cmd(
        "l", "custom_labels",
        "Labels to attach to opencensus metrics <key>:<value>", false,
        "string");
    cmd.add(custom_labels_cmd);
    TCLAP::UnlabeledMultiArg<pid_t> pids_arg(
        "pids", "List of PIDs to be traced.", true, "pid_t");
    cmd.add(pids_arg);
    cmd.add(gcp_creds_cmd);
    cmd.add(gcp_project_cmd);
    cmd.parse(argc, argv);
    file_logging = file_log_switch.getValue();
    gcp_logging = gcp_log_switch.getValue();
    if (gcp_logging == true) {
      std::cerr << "Option -g is deprecated please use -o" << std::endl;
    }
    oc_gcp_logging = oc_gcp_log_switch.getValue();
    gcp_creds = gcp_creds_cmd.getValue();
    gcp_project = gcp_project_cmd.getValue();
    pids = pids_arg.getValue();
    custom_labels = custom_labels_cmd.getValue();
    host_agg = host_agg_switch.getValue();
  } catch (TCLAP::ArgException &e) {
    std::cerr << "error: " << e.error() << " for arg " << e.argId()
              << std::endl;
    return -1;
  }

  if (file_logging) {
    logger = new prober::FileLogger(1, 1048576 * 50, "./logs/");
    metric_exporter =
        new prober::FileMetricExporter(1, 1048576 * 50, "./metrics/");
  } else if (gcp_logging) {
    if (gcp_project.empty()) {
      std::cerr << "GCP project name must be specified" << std::endl;
      return -1;
    }
    logger = new prober::GCPLogger(gcp_project, gcp_creds);
    metric_exporter = new prober::GCPMetricExporter(gcp_project, gcp_creds);
  } else if (oc_gcp_logging) {
    if (gcp_project.empty()) {
      std::cerr << "GCP project name must be specified" << std::endl;
      return -1;
    }
    prober::AggregationLevel agg = prober::AggregationLevel::kConnection;
    if (host_agg) {
      agg = prober::AggregationLevel::kHost;
    }
    logger = new prober::GCPLogger(gcp_project, gcp_creds);
    auto oc_metric_exporter =
        new prober::OCGCPMetricExporter(gcp_project, gcp_creds, agg);
    metric_exporter = oc_metric_exporter;
    absl::flat_hash_map<std::string, std::string> oc_labels;
    for (auto label : custom_labels) {
      auto pos = label.find(":");
      if (pos == std::string::npos) {
        std::cerr << "Delimter : not found for " << label << std::endl;
        return 0;
      }
      oc_labels.insert(
          {label.substr(0, pos), label.substr(pos + 1, std::string::npos)});
    }
    status = oc_metric_exporter->CustomLabels(oc_labels);
    if (!status.ok()) {
      std::cerr << "Error adding custom labels " << status << std::endl;
      return 0;
    }
  } else {
    logger = new prober::StdoutEventExporter();
    metric_exporter = new prober::StdoutMetricExporter();
  }

  if (logger == nullptr || metric_exporter == nullptr) {
    std::cerr << "Count not create exporters" << std::endl;
    return -1;
  }

  status = logger->Init();
  if (!status.ok()) {
    std::cerr << status << std::endl;
    return -1;
  }
  status = metric_exporter->Init();
  if (!status.ok()) {
    std::cerr << status << std::endl;
    return -1;
  }

  prober::MapSource map_source;
  status = map_source.Init();
  if (!status.ok()) {
    std::cerr << status << std::endl;
    return -1;
  }
  status = map_source.LoadObj();
  if (!status.ok()) {
    std::cerr << status << std::endl;
    return -1;
  }
  status = map_source.LoadMaps();
  if (!status.ok()) {
    std::cerr << status << std::endl;
    return -1;
  }
  
  std::vector<prober::DataSource *> sources;
  auto h2_source = new prober::H2GoGrpcSource();
  sources.emplace_back(h2_source);
  sources.emplace_back(&tcp_source);
  correlator.AddSource(prober::Layer::kTCP, &tcp_source);
  correlator.AddSource(prober::Layer::kHTTP2, h2_source);
  for (pid_t pid : pids) {
    status = h2_source->AddPID(pid);
    if (!status.ok()) {
      std::cerr << status << std::endl;
      return -1;
    }
  }

  logger->RegisterCorrelator(&correlator);
  metric_exporter->RegisterCorrelator(&correlator);
  for (auto source : sources) {
    status = source->Init();
    if (!status.ok()) {
      std::cerr << status << std::endl;
      return -1;
    }
    status = source->LoadObj();
    if (!status.ok()) {
      std::cerr << status << std::endl;
      return -1;
    }

    status = source->LoadMaps();
    if (!status.ok()) {
      std::cerr << status << std::endl;
      return -1;
    }

    for (pid_t pid : pids) {
      status = source->FilterPID(pid);
      if (!status.ok()) {
        std::cerr << status << std::endl;
        return -1;
      }
    }
    auto log_sources = source->GetLogSources();
    for (uint32_t i = 0; i < log_sources.size(); i++) {
      if (log_sources[i]->internal_ == false) {
        status = logger->RegisterLog(log_sources[i]->name_,
                                     log_sources[i]->log_desc_);
        if (!status.ok()) {
          if (log_sources[i]->shared_ && !absl::IsAlreadyExists(status)){
            std::cerr << status << std::endl;
            return -1;
          }
        }
      }
      status = data_manager.Register(log_sources[i]);
      if (!status.ok()) {
        std::cerr << status << std::endl;
        return -1;
      }
    }

    auto metric_sources = source->GetMetricSources();
    for (uint32_t i = 0; i < metric_sources.size(); i++) {
      if (metric_sources[i]->internal_ == false) {
        status = metric_exporter->RegisterMetric(
            metric_sources[i]->name_, metric_sources[i]->metric_desc_);
        if (!status.ok()) {
          if (metric_sources[i]->shared_ && !absl::IsAlreadyExists(status)){
            std::cerr << status << std::endl;
            return -1;
          }
        }
      }
      status = data_manager.Register(metric_sources[i]);
      if (!status.ok()) {
        std::cerr << status << std::endl;
        return -1;
      }
    }
  }

  data_manager.AddExternalLogHandler(logger);
  data_manager.AddExternalMetricHandler(metric_exporter);

  status = correlator.Init();
  if (!status.ok()) {
    std::cerr << status << std::endl;
  }

  auto log_sources = correlator.GetLogSources();
  for (auto &source : log_sources) {
    status = data_manager.AddLogHandler(source->name_, &correlator);
    if (!status.ok()) {
      std::cerr << status << std::endl;
    }
  }

  auto metric_sources = correlator.GetMetricSources();
  for (auto &source : metric_sources) {
    status = data_manager.AddMetricHandler(source->name_, &correlator);
    if (!status.ok()) {
      std::cerr << status << std::endl;
    }
  }

  // Probes must be loaded after correlator init
  //  so that we don't miss any messages
  for (auto source : sources) {
    status = source->LoadProbes();
    if (!status.ok()) {
      std::cerr << status << std::endl;
      return -1;
    }
  }

  event_base_dispatch(base);

  return 0;
}
