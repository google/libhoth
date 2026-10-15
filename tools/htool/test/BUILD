load("@rules_cc//cc:cc_library.bzl", "cc_library")

cc_library(
    name = "test_util",
    srcs = ["test_util.cc"],
    hdrs = ["test_util.h"],
    visibility = ["//visibility:public"],
    deps = [
        "//protocol:host_cmd",
        "//protocol/test:libhoth_device_mock",
        "//tools/common:htool_cmd",
        "//tools/htool:htool",
        "//tools/htool:htool_security_version",
        "//transports:libhoth_device",
        "@googletest//:gtest",
    ],
)
