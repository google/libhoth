load("@rules_cc//cc:cc_binary.bzl", "cc_binary")
load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "host_commands",
    textual_hdrs = [
        "host_commands.h",
    ],
    deps = [
        "//protocol:host_cmd",
    ],
)

cc_library(
    name = "srtm",
    srcs = ["htool_srtm.c"],
    hdrs = ["htool_srtm.h"],
    deps = [
        ":host_commands",
    ],
)

config_setting(
    name = "dbus_backend",
    define_values = {
        "dbus_backend": "true",
    },
)

cc_library(
    name = "htool_cmd",
    srcs = ["htool_cmd.c"],
    hdrs = ["htool_cmd.h"],
    deps = ["//:git_version"],
)

cc_library(
    name = "htool_macros",
    hdrs = ["htool_macros.h"],
)

cc_library(
    name = "htool_header",
    hdrs = ["htool.h"],
)

cc_library(
    name = "htool_security_version",
    srcs = ["htool_security_version.c"],
    hdrs = ["htool_security_version.h"],
    deps = [
        ":host_commands",
        ":htool_header",
        "//protocol:host_cmd",
    ],
)

cc_library(
    name = "htool_provisioning",
    srcs = ["htool_provisioning.c"],
    hdrs = ["htool_provisioning.h"],
    deps = [
        ":host_commands",
        ":htool_cmd",
        ":htool_header",
        ":htool_macros",
        ":htool_security_version",
        "//protocol:host_cmd",
        "//transports:libhoth_device",
    ],
)

cc_binary(
    name = "htool",
    srcs = [
        "host_commands.h",
        "htool.c",
        "htool.h",
        "htool_authz_command.c",
        "htool_authz_command.h",
        "htool_cmd.c",
        "htool_cmd.h",
        "htool_console.c",
        "htool_console.h",
        "htool_constants.h",
        "htool_dbus.c",
        "htool_dfu.c",
        "htool_dfu.h",
        "htool_i2c.c",
        "htool_i2c.h",
        "htool_jtag.c",
        "htool_jtag.h",
        "htool_key_rotation.c",
        "htool_key_rotation.h",
        "htool_macros.h",
        "htool_mtd.c",
        "htool_panic.c",
        "htool_panic.h",
        "htool_payload.c",
        "htool_payload.h",
        "htool_payload_update.c",
        "htool_payload_update.h",
        "htool_raw_host_command.c",
        "htool_raw_host_command.h",
        "htool_rot_usb.c",
        "htool_rot_usb.h",
        "htool_sbs_single.c",
        "htool_sbs_single.h",
        "htool_sbs_dual.c",
        "htool_sbs_dual.h",
        "htool_secure_boot.c",
        "htool_secure_boot.h",
        "htool_security_info.c",
        "htool_security_info.h",
        "htool_security_v2.c",
        "htool_security_v2.h",
        "htool_security_version.c",
        "htool_security_version.h",
        "htool_spi.c",
        "htool_statistics.c",
        "htool_statistics.h",
        "htool_target_control.c",
        "htool_target_control.h",
        "htool_update_failure_reasons.h",
        "htool_usb.c",
        "htool_usb.h",
        "htool_provisioning.c",
        "htool_provisioning.h",
    ],
    deps = [
        ":host_commands",
        ":srtm",
        "//:git_version",
        "//protocol:authz_record",
        "//protocol:chipinfo",
        "//protocol:controlled_storage",
        "//protocol:dfu_hostcmd",
        "//protocol:hello",
        "//protocol:host_cmd",
        "//protocol:i2c",
        "//protocol:jtag",
        "//protocol:key_rotation",
        "//protocol:panic",
        "//protocol:payload_info",
        "//protocol:payload_status",
        "//protocol:payload_update",
        "//protocol:progress",
        "//protocol:reboot",
        "//protocol:rot_firmware_version",
        "//protocol:secure_boot",
        "//protocol:spi_proxy",
        "//protocol:statistics",
        "//transports:libhoth_device",
        "//transports:libhoth_mtd",
        "//transports:libhoth_spi",
        "//transports:libhoth_usb",
        "@libusb",
    ] + select({
        ":dbus_backend": ["//transports:libhoth_dbus"],
        "//conditions:default": [],
    }),
)

cc_test(
    name = "htool_provisioning_test",
    srcs = ["htool_provisioning_test.cc"],
    deps = [
        ":htool_cmd",
        ":htool_provisioning",
        ":htool_security_version",
        "//protocol:host_cmd",
        "//protocol/test:libhoth_device_mock",
        "//transports:libhoth_device",
        "//examples/test:test_util",
        "@googletest//:gtest",
        "@googletest//:gtest_main",    ],
)
