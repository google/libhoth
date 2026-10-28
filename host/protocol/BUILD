load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "libhoth_status",
    srcs = ["status.c"],
    hdrs = ["status.h"],
    strip_include_prefix = "/host",
    defines = ["LIBHOTH_SUPPORT_LIBUSB"],
    visibility = ["//visibility:public"],
    deps = [
        "@libusb",
    ],
)

cc_test(
    name = "status_test",
    srcs = ["status_test.cc"],
    deps = [
        ":libhoth_status",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "host_cmd",
    srcs = ["host_cmd.c"],
    hdrs = ["host_cmd.h"],
    strip_include_prefix = "/host",
    deps = [
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "host_cmd_test",
    srcs = ["host_cmd_test.cc"],
    deps = [
        ":host_cmd",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "rot_firmware_version",
    srcs = ["rot_firmware_version.c"],
    hdrs = ["rot_firmware_version.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "rot_firmware_version_test",
    srcs = ["rot_firmware_version_test.cc"],
    deps = [
        ":rot_firmware_version",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "payload_status",
    srcs = ["payload_status.c"],
    hdrs = ["payload_status.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "payload_status_test",
    srcs = ["payload_status_test.cc"],
    deps = [
        ":payload_status",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "panic",
    srcs = ["panic.c"],
    hdrs = ["panic.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "panic_test",
    srcs = ["panic_test.cc"],
    data = [
        "//host/protocol/test:test_data",
    ],
    deps = [
        ":panic",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "payload_update",
    srcs = ["payload_update.c"],
    hdrs = ["payload_update.h"],
    strip_include_prefix = "/host",
    deps = [
        ":command_version",
        ":host_cmd",
        ":libhoth_status",
        ":payload_info",
        ":progress",
        ":util",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "payload_update_test",
    srcs = ["payload_update_test.cc"],
    data = [
        "//host/protocol/test:test_data",
    ],
    deps = [
        ":command_version",
        ":libhoth_status",
        ":payload_info",
        ":payload_update",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "statistics",
    srcs = ["statistics.c"],
    hdrs = ["statistics.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "statistics_test",
    srcs = ["statistics_test.cc"],
    deps = [
        ":statistics",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "reboot",
    srcs = ["reboot.c"],
    hdrs = ["reboot.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "reboot_test",
    srcs = ["reboot_test.cc"],
    deps = [
        ":reboot",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "command_version",
    srcs = ["command_version.c"],
    hdrs = ["command_version.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "command_version_test",
    srcs = ["command_version_test.cc"],
    deps = [
        ":command_version",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "chipinfo",
    srcs = ["chipinfo.c"],
    hdrs = ["chipinfo.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "chipinfo_test",
    srcs = ["chipinfo_test.cc"],
    deps = [
        ":chipinfo",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "i2c",
    srcs = ["i2c.c"],
    hdrs = ["i2c.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "i2c_test",
    srcs = ["i2c_test.cc"],
    deps = [
        ":i2c",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "authz_record",
    srcs = ["authz_record.c"],
    hdrs = ["authz_record.h"],
    strip_include_prefix = "/host",
    deps = [
        ":chipinfo",
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "authz_record_test",
    srcs = ["authz_record_test.cc"],
    deps = [
        ":authz_record",
        ":chipinfo",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "progress",
    srcs = ["progress.c"],
    hdrs = ["progress.h"],
    strip_include_prefix = "/host",
)

cc_test(
    name = "progress_test",
    srcs = ["progress_test.cc"],
    deps = [
        ":progress",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "spi_proxy",
    srcs = ["spi_proxy.c"],
    hdrs = ["spi_proxy.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        ":progress",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "spi_proxy_test",
    srcs = ["spi_proxy_test.cc"],
    deps = [
        ":libhoth_status",
        ":spi_proxy",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "payload_info",
    srcs = ["payload_info.c"],
    hdrs = ["payload_info.h"],
    strip_include_prefix = "/host",
)

cc_test(
    name = "payload_info_test",
    srcs = ["payload_info_test.cc"],
    data = [
        "//host/protocol/test:test_data",
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
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        ":progress",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "controlled_storage_test",
    srcs = ["controlled_storage_test.cc"],
    deps = [
        ":controlled_storage",
        ":libhoth_status",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "firmware_update",
    srcs = ["firmware_update.c"],
    hdrs = ["firmware_update.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "firmware_update_test",
    srcs = ["firmware_update_test.cc"],
    deps = [
        ":firmware_update",
        ":host_cmd",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "jtag",
    srcs = ["jtag.c"],
    hdrs = ["jtag.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "jtag_test",
    srcs = ["jtag_test.cc"],
    deps = [
        ":jtag",
        ":libhoth_status",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "hello",
    srcs = ["hello.c"],
    hdrs = ["hello.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "hello_test",
    srcs = ["hello_test.cc"],
    deps = [
        ":hello",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "gpio_drive_strength",
    srcs = ["gpio_drive_strength.c"],
    hdrs = ["gpio_drive_strength.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "gpio_drive_strength_test",
    srcs = ["gpio_drive_strength_test.cc"],
    deps = [
        ":gpio_drive_strength",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "opentitan_version",
    srcs = ["opentitan_version.c"],
    hdrs = [
        "console.h",
        "opentitan_manifest.h",
        "opentitan_version.h",
    ],
    strip_include_prefix = "/host",
    deps = [
        ":console",
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "opentitan_version_test",
    srcs = ["opentitan_version_test.cc"],
    deps = [
        ":libhoth_status",
        ":opentitan_version",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "key_rotation",
    srcs = ["key_rotation.c"],
    hdrs = ["key_rotation.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "key_rotation_test",
    srcs = ["key_rotation_test.cc"],
    deps = [
        ":host_cmd",
        ":key_rotation",
        ":libhoth_status",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "secure_boot",
    srcs = ["secure_boot.c"],
    hdrs = ["secure_boot.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "secure_boot_test",
    srcs = ["secure_boot_test.cc"],
    deps = [
        ":host_cmd",
        ":secure_boot",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "console",
    srcs = ["console.c"],
    hdrs = ["console.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        ":util",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "console_test",
    srcs = ["console_test.cc"],
    deps = [
        ":console",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)


cc_library(
    name = "dfu_hostcmd",
    srcs = ["dfu_hostcmd.c"],
    hdrs = ["dfu_hostcmd.h"],
    strip_include_prefix = "/host",
    deps = [
        ":dfu_check",
        ":host_cmd",
        ":libhoth_status",
        ":opentitan_version",
        "//host/transports:libhoth_device",
    ],
)

cc_library(
    name = "dfu_check",
    srcs = [
        "dfu_check.c",
    ],
    hdrs = [
        "dfu_check.h",
    ],
    strip_include_prefix = "/host",
    deps = [
        ":console",
        ":libhoth_status",
        ":opentitan_version",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "dfu_check_test",
    srcs = ["dfu_check_test.cc"],
    data = [
        "//host/protocol/test:test_data",
    ],
    deps = [
        ":dfu_check",
        ":host_cmd",
        ":opentitan_version",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "util",
    srcs = ["util.c"],
    hdrs = ["util.h"],
    strip_include_prefix = "/host",
)

cc_library(
    name = "mauv",
    srcs = ["mauv.c"],
    hdrs = ["mauv.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "mauv_test",
    srcs = ["mauv_test.cc"],
    deps = [
        ":mauv",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "update_session",
    srcs = ["update_session.c"],
    hdrs = ["update_session.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "update_session_test",
    srcs = ["update_session_test.cc"],
    deps = [
        ":host_cmd",
        ":libhoth_status",
        ":update_session",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "target_watchdog",
    srcs = ["target_watchdog.c"],
    hdrs = ["target_watchdog.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "target_watchdog_test",
    srcs = ["target_watchdog_test.cc"],
    deps = [
        ":host_cmd",
        ":libhoth_status",
        ":target_watchdog",
        "//host/protocol/test:libhoth_device_mock",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "provisioning",
    srcs = ["provisioning.c"],
    hdrs = ["provisioning.h"],
    strip_include_prefix = "/host",
    deps = [
        ":host_cmd",
        ":libhoth_status",
        "//host/transports:libhoth_device",
    ],
)
