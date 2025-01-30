package(default_visibility = ["//visibility:public"])

cc_library(
    name = "host_cmd",
    hdrs = ["host_cmd.h"],
    srcs = ["host_cmd.c"],
    deps = [
        "//transports:libhoth_device",
    ],
)

cc_library(
    name = "firmware_version",
    hdrs = ["firmware_version.h"],
    srcs = ["firmware_version.c"],
    deps = [
        "//transports:libhoth_device",
        ":host_cmd",
    ],
)
