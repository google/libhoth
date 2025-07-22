load("@rules_cc//cc:cc_library.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "libhoth_device_mock",
    srcs = ["libhoth_device_mock.cc"],
    hdrs = ["libhoth_device_mock.h"],
    deps = [
        "//protocol:host_cmd",
        "//transports:libhoth_device",
        "@googletest//:gtest",
    ],
)

filegroup(
    name = "test_data",
    srcs = glob(["*.bin"]),
)
