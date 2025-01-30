package(default_visibility = ["//visibility:public"])

cc_library(
    name = "host_commands",
    textual_hdrs = [
        "host_commands.h",
        "authorization_record.h",
    ],
    deps = [
        "//protocol:host_cmd",
    ],
)

cc_library(
    name = "authorization_record",
    hdrs = ["authorization_record.h"],
    srcs = ["authorization_record.c"],
)

cc_library(
    name = "srtm",
    hdrs = ["htool_srtm.h"],
    srcs = ["htool_srtm.c"],
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

cc_binary(
    name = "htool",
    srcs = [
        "authorization_record.h",
        "authorization_record.c",
        "host_commands.h",
        "htool.c",
        "htool.h",
        "htool_authz_command.h",
        "htool_authz_command.c",
        "htool_cmd.c",
        "htool_cmd.h",
        "htool_console.c",
        "htool_console.h",
        "htool_constants.h",
        "htool_i2c.c",
        "htool_i2c.h",
        "htool_jtag.h",
        "htool_jtag.c",
        "htool_mtd.c",
        "htool_panic.c",
        "htool_panic.h",
        "htool_payload.c",
        "htool_payload.h",
        "htool_payload_update.c",
        "htool_payload_update.h",
        "htool_progress.c",
        "htool_progress.h",
        "htool_raw_host_command.c",
        "htool_raw_host_command.h",
        "htool_spi.c",
        "htool_spi_proxy.c",
        "htool_spi_proxy.h",
        "htool_statistics.c",
        "htool_statistics.h",
        "htool_target_control.c",
        "htool_target_control.h",
        "htool_target_usb.c",
        "htool_target_usb.h",
        "htool_update_failure_reasons.h",
        "htool_usb.c",
        "htool_usb.h",
        "htool_dbus.c",
    ],
    deps = [
        ":authorization_record",
        ":host_commands",
        ":srtm",
        "//:git_version",
        "//protocol:host_cmd",
        "//protocol:firmware_version",
        "//transports:libhoth_device",
        "//transports:libhoth_mtd",
        "//transports:libhoth_spi",
        "//transports:libhoth_usb",
        "@libusb//:libusb",
    ] + select({
        ":dbus_backend": ["//transports:libhoth_dbus"],
        "//conditions:default": [],
    }),
)
