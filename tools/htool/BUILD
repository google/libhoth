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
        "//host/protocol:console",
        "//host/protocol:host_cmd",
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
    name = "htool_header",
    hdrs = ["htool.h"],
    deps = [
        "//host/protocol:libhoth_status",
    ],
)

cc_library(
    name = "htool_security_version",
    srcs = ["htool_security_version.c"],
    hdrs = ["htool_security_version.h"],
    deps = [
        ":host_commands",
        ":htool_header",
        "//host/protocol:host_cmd",
        "//host/protocol:libhoth_status",
    ],
)

cc_library(
    name = "htool_provisioning",
    srcs = ["htool_provisioning.c"],
    hdrs = ["htool_provisioning.h"],
    deps = [
        ":htool_header",
        "//host/protocol:libhoth_status",
        "//host/protocol:provisioning",
        "//tools/common:htool_cmd",
        "//tools/common:macros",
        "//host/transports:libhoth_device",
    ],
)

cc_library(
    name = "htool_security_v2",
    srcs = ["htool_security_v2.c"],
    hdrs = ["htool_security_v2.h"],
    deps = [
        ":host_commands",
        ":htool_header",
        "//host/protocol:host_cmd",
        "//host/protocol:libhoth_status",
        "//host/transports:libhoth_device",
    ],
)

cc_library(
    name = "htool_security_v2_defs",
    hdrs = ["htool_security_v2_defs.h"],
)

cc_library(
    name = "htool_security_certificates",
    srcs = ["htool_security_certificates.c"],
    hdrs = ["htool_security_certificates.h"],
    deps = [
        ":host_commands",
        ":htool_header",
        ":htool_security_v2",
        ":htool_security_v2_defs",
        ":htool_security_version",
        "//host/protocol:host_cmd",
        "//tools/common:htool_cmd",
        "//tools/common:macros",
    ],
)

cc_library(
    name = "htool_security_tokens",
    srcs = ["htool_security_tokens.c"],
    hdrs = ["htool_security_tokens.h"],
    deps = [
        ":host_commands",
        ":htool_header",
        ":htool_security_v2",
        ":htool_security_v2_defs",
        ":htool_security_version",
        "//host/protocol:host_cmd",
        "//tools/common:htool_cmd",
        "//tools/common:macros",
        "//host/transports:libhoth_device",
    ],
)

cc_test(
    name = "htool_security_certificates_test",
    srcs = ["htool_security_certificates_test.cc"],
    deps = [
        ":htool_security_certificates",
        ":htool_security_v2",
        ":htool_security_version",
        "//host/protocol/test:libhoth_device_mock",
        "//tools/htool/test:test_util",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "htool_security_tokens_test",
    srcs = ["htool_security_tokens_test.cc"],
    deps = [
        ":htool_security_tokens",
        ":htool_security_v2",
        ":htool_security_version",
        "//host/protocol/test:libhoth_device_mock",
        "//tools/htool/test:test_util",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "htool_security_v2_test",
    srcs = ["htool_security_v2_test.cc"],
    deps = [
        ":host_commands",
        ":htool_security_v2",
        ":htool_security_version",
        "//host/protocol/test:libhoth_device_mock",
        "//tools/htool/test:test_util",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

# All of htool, including main(). A library so the //examples:htool compat
# target can link the same binary.
cc_library(
    name = "htool_lib",
    srcs = [
        "host_commands.h",
        "htool.c",
        "htool.h",
        "htool_authz_command.c",
        "htool_authz_command.h",
        "htool_console.c",
        "htool_console.h",
        "htool_constants.h",
        "htool_dbus.c",
        "htool_debug.c",
        "htool_debug.h",
        "htool_dfu.c",
        "htool_dfu.h",
        "htool_firmware_update.c",
        "htool_firmware_update.h",
        "htool_i2c.c",
        "htool_i2c.h",
        "htool_jtag.c",
        "htool_jtag.h",
        "htool_key_rotation.c",
        "htool_key_rotation.h",
        "htool_mauv.c",
        "htool_mauv.h",
        "htool_mtd.c",
        "htool_panic.c",
        "htool_panic.h",
        "htool_payload.c",
        "htool_payload.h",
        "htool_payload_update.c",
        "htool_payload_update.h",
        "htool_provisioning.c",
        "htool_provisioning.h",
        "htool_raw_host_command.c",
        "htool_raw_host_command.h",
        "htool_rot_usb.c",
        "htool_rot_usb.h",
        "htool_sbs_dual.c",
        "htool_sbs_dual.h",
        "htool_sbs_single.c",
        "htool_sbs_single.h",
        "htool_secure_boot.c",
        "htool_secure_boot.h",
        "htool_security_certificates.c",
        "htool_security_certificates.h",
        "htool_security_info.c",
        "htool_security_info.h",
        "htool_security_tokens.c",
        "htool_security_tokens.h",
        "htool_security_v2.c",
        "htool_security_v2.h",
        "htool_security_v2_defs.h",
        "htool_security_version.c",
        "htool_security_version.h",
        "htool_spi.c",
        "htool_statistics.c",
        "htool_statistics.h",
        "htool_target_control.c",
        "htool_target_control.h",
        "htool_target_watchdog.c",
        "htool_target_watchdog.h",
        "htool_tpm.c",
        "htool_tpm.h",
        "htool_update_failure_reasons.h",
        "htool_update_session.c",
        "htool_update_session.h",
        "htool_usb.c",
        "htool_usb.h",
    ],
    features = ["fully_static_link_target"],
    deps = [
        ":host_commands",
        ":srtm",
        "//:git_version",
        "//host/protocol:authz_record",
        "//host/protocol:chipinfo",
        "//host/protocol:console",
        "//host/protocol:controlled_storage",
        "//host/protocol:dfu_check",
        "//host/protocol:dfu_hostcmd",
        "//host/protocol:firmware_update",
        "//host/protocol:gpio_drive_strength",
        "//host/protocol:hello",
        "//host/protocol:host_cmd",
        "//host/protocol:i2c",
        "//host/protocol:jtag",
        "//host/protocol:key_rotation",
        "//host/protocol:libhoth_status",
        "//host/protocol:mauv",
        "//host/protocol:opentitan_version",
        "//host/protocol:panic",
        "//host/protocol:payload_info",
        "//host/protocol:payload_status",
        "//host/protocol:payload_update",
        "//host/protocol:progress",
        "//host/protocol:provisioning",
        "//host/protocol:reboot",
        "//host/protocol:rot_firmware_version",
        "//host/protocol:secure_boot",
        "//host/protocol:spi_proxy",
        "//host/protocol:statistics",
        "//host/protocol:target_watchdog",
        "//host/protocol:update_session",
        "//host/protocol:util",
        "//tools/common:htool_cmd",
        "//tools/common:macros",
        "//host/transports:libhoth_device",
        "//host/transports:libhoth_mtd",
        "//host/transports:libhoth_spi",
        "//host/transports:libhoth_usb",
        "//host/transports:libhoth_usb_device",
        "@libusb",
    ] + select({
        ":dbus_backend": ["//host/transports:libhoth_dbus"],
        "//conditions:default": [],
    }),
)

cc_binary(
    name = "htool",
    features = ["fully_static_link_target"],
    deps = [":htool_lib"],
)

cc_test(
    name = "htool_provisioning_test",
    srcs = ["htool_provisioning_test.cc"],
    deps = [
        ":host_commands",
        ":htool_provisioning",
        "//host/protocol:host_cmd",
        "//host/protocol/test:libhoth_device_mock",
        "//tools/common:htool_cmd",
        "//tools/htool/test:test_util",
        "//host/transports:libhoth_device",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "htool_target_watchdog",
    srcs = ["htool_target_watchdog.c"],
    hdrs = ["htool_target_watchdog.h"],
    deps = [
        ":htool_header",
        "//host/protocol:host_cmd",
        "//host/protocol:libhoth_status",
        "//host/protocol:target_watchdog",
        "//tools/common:htool_cmd",
        "//host/transports:libhoth_device",
    ],
)
