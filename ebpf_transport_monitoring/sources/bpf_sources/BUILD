load("//rules:bpf.bzl", "bpf_program")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "missing_headers",
    hdrs = [
        "missing_defs.h",
        "struct_flavors.h",
    ],
)

cc_library(
    name = "maps",
    hdrs = [
        "maps.h",
    ],
)

cc_library(
    name = "parse_h2_frame",
    hdrs = [
        "parse_h2_frame.h",
    ],
)

bpf_program(
    name = "tcp_bpf_core",
    src = "tcp_bpf.c",
    core = True,
    deps = [
        ":maps",
        ":missing_headers",
        "//:events",
        "//sources/common:correlator_types",
        "//sources/common:defines",
        "//sources/common:syms",
        "//sources/common:vmlinux",
        "@libbpf",
    ],
)


bpf_program(
    name = "tcp_bpf",
    src = "tcp_bpf.c",
    core = False,
    deps = [
        ":maps",
        "//:events",
        "//sources/common:correlator_types",
        "//sources/common:defines",
        "//sources/common:syms",
        "//third_party/include:stdarg",
        "@libbpf",
    ],
)

bpf_program(
    name = "tcp_bpf_kprobe_core",
    src = "tcp_bpf_kprobe.c",
    core = True,
    deps = [
        ":missing_headers",
        "//:events",
        "//sources/common:correlator_types",
        "//sources/common:defines",
        "//sources/common:syms",
        "//sources/common:vmlinux",
        "@libbpf",
    ],
)

bpf_program(
    name = "tcp_bpf_kprobe",
    src = "tcp_bpf_kprobe.c",
    core = False,
    deps = [
        "//:events",
        "//sources/common:correlator_types",
        "//sources/common:defines",
        "//sources/common:syms",
        "//third_party/include:stdarg",
        "@libbpf",
    ],
)

bpf_program(
    name = "h2_bpf_core",
    src = "h2_bpf.c",
    core = True,
    deps = [
        ":maps",
        ":parse_h2_frame",
        ":missing_headers",
        "//:events",
        "//sources/common:correlator_types",
        "//sources/common:defines",
        "//sources/common:syms",
        "//sources/common:vmlinux",
        "@libbpf",
    ],
)

bpf_program(
    name = "h2_bpf",
    src = "h2_bpf.c",
    core = False,
    deps = [
       ":maps",
       ":parse_h2_frame",
        "//:events",
        "//sources/common:correlator_types",
        "//sources/common:defines",
        "//sources/common:syms",
        "//third_party/include:stdarg",
        "@libbpf",
    ],
)

bpf_program(
    name = "maps_core",
    src = "maps.c",
    core = True,
    deps = [
        ":maps",
        "//:events",
        "//sources/common:vmlinux",
        "//sources/common:defines",
        "@libbpf",
        "//third_party/include:stdarg",
    ],
)

bpf_program(
    name = "maps_bpf",
    src = "maps.c",
    core = False,
    deps = [
        ":maps",
        "//:events",
        "//sources/common:vmlinux",
        "//sources/common:defines",
        "@libbpf",
        "//third_party/include:stdarg",
    ],
)
