load("@rules_cc//cc:cc_library.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "libhoth_device_mock",
    srcs = ["libhoth_device_mock.cc"],
    hdrs = ["libhoth_device_mock.h"],
    strip_include_prefix = "/host",
    deps = [
        "//host/protocol:host_cmd",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
    ],
)

filegroup(
    name = "test_data",
    srcs = glob(["*.bin"]),
)
