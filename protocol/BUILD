load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "host_cmd",
    srcs = ["host_cmd.c"],
    hdrs = ["host_cmd.h"],
    deps = [
        "//transports:libhoth_device",
    ],
)

cc_test(
    name = "host_cmd_test",
    srcs = ["host_cmd_test.cc"],
    deps = [
        ":host_cmd",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "rot_firmware_version",
    srcs = ["rot_firmware_version.c"],
    hdrs = ["rot_firmware_version.h"],
    deps = [
        ":host_cmd",
        "//transports:libhoth_device",
    ],
)

cc_test(
    name = "rot_firmware_version_test",
    srcs = ["rot_firmware_version_test.cc"],
    deps = [
        ":rot_firmware_version",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "payload_status",
    srcs = ["payload_status.c"],
    hdrs = ["payload_status.h"],
    deps = [
        ":host_cmd",
        "//transports:libhoth_device",
    ],
)

cc_test(
    name = "payload_status_test",
    srcs = ["payload_status_test.cc"],
    deps = [
        ":payload_status",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "panic",
    srcs = ["panic.c"],
    hdrs = ["panic.h"],
    deps = [
        ":host_cmd",
        "//transports:libhoth_device",
    ],
)

cc_test(
    name = "panic_test",
    srcs = ["panic_test.cc"],
    data = [
        "//protocol/test:test_data",
    ],
    deps = [
        ":panic",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "payload_update",
    srcs = ["payload_update.c"],
    hdrs = ["payload_update.h"],
    deps = [
        ":command_version",
        ":host_cmd",
        ":payload_info",
        "//transports:libhoth_device",
    ],
)

cc_test(
    name = "payload_update_test",
    srcs = ["payload_update_test.cc"],
    data = [
        "//protocol/test:test_data",
    ],
    deps = [
        ":command_version",
        ":payload_update",
        "//protocol/test:libhoth_device_mock",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "statistics",
    srcs = ["statistics.c"],
    hdrs = ["statistics.h"],
    deps = [
        ":host_cmd",
        "//transports:libhoth_device",
    ],
)

cc_test(
    name = "statistics_test",
    srcs = ["statistics_test.cc"],
    deps = [
        ":statistics",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "reboot",
    srcs = ["reboot.c"],
    hdrs = ["reboot.h"],
    deps = [
        ":host_cmd",
        "//transports:libhoth_device",
    ],
)

cc_test(
    name = "reboot_test",
    srcs = ["reboot_test.cc"],
    deps = [
        ":reboot",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "command_version",
    srcs = ["command_version.c"],
    hdrs = ["command_version.h"],
    deps = [
        ":host_cmd",
        "//transports:libhoth_device",
    ],
)

cc_test(
    name = "command_version_test",
    srcs = ["command_version_test.cc"],
    deps = [
        ":command_version",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "chipinfo",
    srcs = ["chipinfo.c"],
    hdrs = ["chipinfo.h"],
    deps = [
        ":host_cmd",
        "//transports:libhoth_device",
    ],
)

cc_test(
    name = "chipinfo_test",
    srcs = ["chipinfo_test.cc"],
    deps = [
        ":chipinfo",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "i2c",
    srcs = ["i2c.c"],
    hdrs = ["i2c.h"],
    deps = [
        ":host_cmd",
        "//transports:libhoth_device",
    ],
)

cc_test(
    name = "i2c_test",
    srcs = ["i2c_test.cc"],
    deps = [
        ":i2c",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "authz_record",
    srcs = ["authz_record.c"],
    hdrs = ["authz_record.h"],
    deps = [
        ":chipinfo",
        ":host_cmd",
        "//transports:libhoth_device",
    ],
)

cc_test(
    name = "authz_record_test",
    srcs = ["authz_record_test.cc"],
    deps = [
        ":authz_record",
        ":chipinfo",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "progress",
    srcs = ["progress.c"],
    hdrs = ["progress.h"],
)

cc_library(
    name = "spi_proxy",
    srcs = ["spi_proxy.c"],
    hdrs = ["spi_proxy.h"],
    deps = [
        ":host_cmd",
        ":progress",
        "//transports:libhoth_device",
    ],
)

cc_test(
    name = "spi_proxy_test",
    srcs = ["spi_proxy_test.cc"],
    deps = [
        ":spi_proxy",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "payload_info",
    srcs = ["payload_info.c"],
    hdrs = ["payload_info.h"],
)

cc_test(
    name = "payload_info_test",
    srcs = ["payload_info_test.cc"],
    data = [
        "//protocol/test:test_data",
    ],
    deps = [
        ":payload_info",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "controlled_storage",
    srcs = ["controlled_storage.c"],
    hdrs = ["controlled_storage.h"],
    deps = [
        ":host_cmd",
        ":progress",
        "//transports:libhoth_device",
    ],
)

cc_test(
    name = "controlled_storage_test",
    srcs = ["controlled_storage_test.cc"],
    deps = [
        ":controlled_storage",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "jtag",
    srcs = ["jtag.c"],
    hdrs = ["jtag.h"],
    deps = [
        ":host_cmd",
        "//transports:libhoth_device",
    ],
)

cc_test(
    name = "jtag_test",
    srcs = ["jtag_test.cc"],
    deps = [
        ":jtag",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "hello",
    srcs = ["hello.c"],
    hdrs = ["hello.h"],
    deps = [
        ":host_cmd",
        "//transports:libhoth_device",
    ],
)

cc_test(
    name = "hello_test",
    srcs = ["hello_test.cc"],
    deps = [
        ":hello",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "key_rotation",
    srcs = ["key_rotation.c"],
    hdrs = ["key_rotation.h"],
    deps = [
        ":host_cmd",
        "//transports:libhoth_device",
    ],
)

cc_test(
    name = "key_rotation_test",
    srcs = ["key_rotation_test.cc"],
    deps = [
        ":host_cmd",
        ":key_rotation",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "secure_boot",
    srcs = ["secure_boot.c"],
    hdrs = ["secure_boot.h"],
    deps = [
        ":host_cmd",
        "//transports:libhoth_device",
    ],
)

cc_test(
    name = "secure_boot_test",
    srcs = ["secure_boot_test.cc"],
    deps = [
        ":host_cmd",
        ":secure_boot",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)
