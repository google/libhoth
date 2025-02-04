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
    name = "rot_firmware_version",
    hdrs = ["rot_firmware_version.h"],
    srcs = ["rot_firmware_version.c"],
    deps = [
        "//transports:libhoth_device",
        ":host_cmd",
    ],
)

cc_test(
    name = "rot_firmware_version_test",
    srcs = ["rot_firmware_version_test.cc"],
    deps = [
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "//transports:libhoth_device",
        "//protocol/test:libhoth_device_mock",
        ":rot_firmware_version",
    ],
)

cc_library(
    name = "payload_status",
    hdrs = ["payload_status.h"],
    srcs = ["payload_status.c"],
    deps = [
        "//transports:libhoth_device",
        ":host_cmd",
    ],
)

cc_test(
    name = "payload_status_test",
    srcs = ["payload_status_test.cc"],
    deps = [
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "//transports:libhoth_device",
        "//protocol/test:libhoth_device_mock",
        ":payload_status",
    ],
)
