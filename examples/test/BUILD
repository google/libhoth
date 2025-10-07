cc_library(
    name = "test_util",
    srcs = ["test_util.cc"],
    hdrs = ["test_util.h"],
    visibility = ["//visibility:public"],
    deps = [
        "//examples:htool",
        "//examples:htool_cmd",
        "//examples:htool_security_version",
        "//protocol:host_cmd",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "@googletest//:gtest",
    ],
)
