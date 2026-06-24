load("@rules_cc//cc:cc_library.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

exports_files([
    "external/libusb.BUILD",
    "external/libusb.patch",
])

cc_library(
    name = "git_version",
    hdrs = [":gen_version_header"],
)

genrule(
    name = "gen_version_header",
    outs = ["git_version.h"],
    cmd = "$(location :print_version_header.sh) > \"$@\"",
    stamp = 1,
    tools = [":print_version_header.sh"],
)

cc_library(
    name = "libhoth_protocol",
    hdrs = [
        "//protocol:headers",
    ],
    include_prefix = "libhoth/protocol",
    strip_include_prefix = "protocol",
    deps = [
        "//protocol:authz_record",
        "//protocol:chipinfo",
        "//protocol:console",
        "//protocol:controlled_storage",
        "//protocol:dfu_check",
        "//protocol:dfu_hostcmd",
        "//protocol:firmware_update",
        "//protocol:gpio_drive_strength",
        "//protocol:hello",
        "//protocol:host_cmd",
        "//protocol:i2c",
        "//protocol:jtag",
        "//protocol:key_rotation",
        "//protocol:libhoth_status",
        "//protocol:mauv",
        "//protocol:opentitan_version",
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
        "//protocol:util",
        "//transports:libhoth_device",
        "//transports:libhoth_device_headers_legacy",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "libhoth_usb",
    deps = [
        "//transports:libhoth_usb",
        "//transports:libhoth_usb_device",
        "//transports:libhoth_usb_headers_legacy",
        "//transports:libhoth_device_headers_legacy",
        "@libusb//:libusb",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "libhoth_spi",
    deps = [
        "//transports:libhoth_spi",
        "//transports:libhoth_spi_headers_legacy",
        "//transports:libhoth_device_headers_legacy",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "libhoth_mtd",
    deps = [
        "//transports:libhoth_mtd",
        "//transports:libhoth_mtd_headers_legacy",
        "//transports:libhoth_device_headers_legacy",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "libhoth_dbus",
    deps = [
        "//transports:libhoth_dbus",
        "//transports:libhoth_dbus_headers_legacy",
        "//transports:libhoth_device_headers_legacy",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "libhoth",
    deps = [
        ":libhoth_protocol",
        ":libhoth_usb",
        ":libhoth_spi",
        ":libhoth_mtd",
    ] + select({
        "//examples:dbus_backend": [":libhoth_dbus"],
        "//conditions:default": [],
    }),
    visibility = ["//visibility:public"],
)

alias(
    name = "libusb",
    actual = "@libusb//:libusb",
    visibility = ["//visibility:public"],
)
