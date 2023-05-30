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

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "btf_min",
    alwayslink = True,
    deps = [":reduced_btf"]
)

genrule(
    name = "reduced_btf",
    srcs = ["reduced_btfs.tar.gz"],
    outs = ["reduced_btf.o"],
    cmd = "ld -r -b binary $(locations reduced_btfs.tar.gz) -o $@",
)

cc_library(
    name = "probes",
    hdrs = ["probes.h"],
    deps = [
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
        "@libbpf",
    ],
)

cc_library(
    name = "data_source",
    srcs = ["data_source.cc"],
    hdrs = ["data_source.h"],
    deps = [
        ":map_memory",
        ":btf_min",
        ":source_helper",
        ":os_helper",
        "archive_handler",
        "//loader/exporter:data_types",
        "//loader/source:probes",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/time",
        "@libbpf",
    ],
)

cc_library(
    name = "source_helper",
    srcs = ["source_helper.cc"],
    hdrs = ["source_helper.h"],
    deps = [
        "@libbpf",
        ":elf_reader",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_re2//:re2",
    ],
)

cc_library(
    name = "sym_addrs",
    hdrs = ["sym_addrs.h"],
)

cc_library(
    name = "map_memory",
    hdrs = ["map_memory.h"],
)

cc_library(
    name = "elf_reader",
    srcs = ["elf_reader.cc"],
    hdrs = ["elf_reader.h"],
    deps = [
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@elfutils//:libelf",
    ],
)

cc_binary(
    name = "elf_reader_tool",
    srcs = ["elf_reader_tool.cc"],
    deps = [
        ":elf_reader",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@zlib",
    ],
)

cc_library(
    name = "dwarf_reader",
    srcs = ["dwarf_reader.cc"],
    hdrs = ["dwarf_reader.h"],
    deps = [
        ":sym_addrs",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@elfutils//:libelf",
        "@zlib//:zlib"
    ],
)

cc_binary(
    name = "dwarf_reader_tool",
    srcs = ["dwarf_reader_tool.cc"],
    linkstatic = True,
    deps = [
        ":dwarf_reader",
        ":sym_addrs",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_library(
    name = "proc_reader",
    srcs = ["proc_reader.cc"],
    hdrs = ["proc_reader.h"],
    deps = [
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "archive_handler",
    srcs = ["archive_handler.cc"],
    hdrs = ["archive_handler.h"],
    deps = [        
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_github_libarchive//:libarchive",
    ],
)

cc_library(
    name = "os_helper",
    srcs = ["os_helper.cc"],
    hdrs = ["os_helper.h"],
    deps = [        
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_re2//:re2",
    ],
)

