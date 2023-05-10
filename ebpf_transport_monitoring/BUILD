# Copyright 2023 Google LLC
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# eBPF code for observability.

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "events",
    hdrs = ["events.h"],
)

cc_library(
    name = "data_manager",
    srcs = ["data_manager.cc"],
    hdrs = ["data_manager.h"],
    deps = [
        "//loader/exporter:data_types",
        "//loader/exporter:log_exporter",
        "//loader/exporter:metric_exporter",
        "//loader/source:data_source",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/time",
        "@libbpf",
        "@libevent",
    ],
)

cc_binary(
    name = "lightfoot",
    srcs = [
        "lightfoot.cc",
    ],
    linkstatic = True,
    deps = [
        ":data_manager",
        "//correlators:h2_go_correlator",
        "//exporters:file_exporter",
        "//exporters:gcp_exporter",
        "//exporters:oc_gcp_exporter",
        "//exporters:stdout_event_logger",
        "//exporters:stdout_metric_exporter",
        "//loader/source:data_source",
        "//sources/source_manager:h2_go_grpc_source",
        "//sources/source_manager:tcp_source",
        "//sources/source_manager:map_source",
        "@com_github_tclap_tclap//:tclap",
        "@zlib//:zlib"
    ],
)
