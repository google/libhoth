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

cc_library(
    name = "panic",
    hdrs = ["panic.h"],
    srcs = ["panic.c"],
    deps = [
        "//transports:libhoth_device",
        ":host_cmd",
    ],
)

cc_test(
    name = "panic_test",
    srcs = ["panic_test.cc"],
    deps = [
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "//transports:libhoth_device",
        "//protocol/test:libhoth_device_mock",
        ":panic",
    ],
    data = [
        "//protocol/test:test_data",
    ],
)

cc_library(
    name = "payload_update",
    hdrs = ["payload_update.h"],
    srcs = ["payload_update.c"],
    deps = [
        "//transports:libhoth_device",
        ":host_cmd",
    ],
)

cc_test(
    name = "payload_update_test",
    srcs = ["payload_update_test.cc"],
    deps = [
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "//transports:libhoth_device",
        "//protocol/test:libhoth_device_mock",
        ":payload_update",
    ],
    data = [
        "//protocol/test:test_data",
    ],
)

cc_library(
    name = "statistics",
    hdrs = ["statistics.h"],
    srcs = ["statistics.c"],
    deps = [
        "//transports:libhoth_device",
        ":host_cmd",
    ],
)

cc_test(
    name = "statistics_test",
    srcs = ["statistics_test.cc"],
    deps = [
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "//transports:libhoth_device",
        "//protocol/test:libhoth_device_mock",
        ":statistics",
    ],
)

cc_library(
    name = "reboot",
    hdrs = ["reboot.h"],
    srcs = ["reboot.c"],
    deps = [
        "//transports:libhoth_device",
        ":host_cmd",
    ],
)

cc_test(
    name = "reboot_test",
    srcs = ["reboot_test.cc"],
    deps = [
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "//transports:libhoth_device",
        "//protocol/test:libhoth_device_mock",
        ":reboot",
    ],
)

cc_library(
    name = "chipinfo",
    hdrs = ["chipinfo.h"],
    srcs = ["chipinfo.c"],
    deps = [
        "//transports:libhoth_device",
        ":host_cmd",
    ],
)

cc_test(
    name = "chipinfo_test",
    srcs = ["chipinfo_test.cc"],
    deps = [
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "//transports:libhoth_device",
        "//protocol/test:libhoth_device_mock",
        ":chipinfo",
    ],
)

cc_library(
    name = "i2c",
    hdrs = ["i2c.h"],
    srcs = ["i2c.c"],
    deps = [
        "//transports:libhoth_device",
        ":host_cmd",
    ],
)

cc_test(
    name = "i2c_test",
    srcs = ["i2c_test.cc"],
    deps = [
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "//transports:libhoth_device",
        "//protocol/test:libhoth_device_mock",
        ":i2c",
    ],
)

cc_library(
    name = "authz_record",
    hdrs = ["authz_record.h"],
    srcs = ["authz_record.c"],
    deps = [
        "//transports:libhoth_device",
        ":host_cmd",
        ":chipinfo",
    ],
)

cc_test(
    name = "authz_record_test",
    srcs = ["authz_record_test.cc"],
    deps = [
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "//transports:libhoth_device",
        "//protocol/test:libhoth_device_mock",
        ":authz_record",
    ],
)

cc_library(
    name = "progress",
    hdrs = ["progress.h"],
    srcs = ["progress.c"],
)

