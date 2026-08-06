load("@rules_cc//cc:cc_library.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "libhoth_device",
    srcs = ["libhoth_device.c"],
    hdrs = ["libhoth_device.h"],
    include_prefix = "libhoth/transports",
    strip_include_prefix = ".",
    deps = [
        "//protocol:libhoth_status",
    ],
)

cc_library(
    name = "libhoth_device_headers_legacy",
    hdrs = [
        "libhoth_device.h",
        "libhoth_ec.h",
    ],
    include_prefix = "transports",
    strip_include_prefix = ".",
)

cc_library(
    name = "libhoth_ec",
    hdrs = ["libhoth_ec.h"],
    include_prefix = "libhoth/transports",
    strip_include_prefix = ".",
)

cc_library(
    name = "libhoth_mtd",
    srcs = ["libhoth_mtd.c"],
    hdrs = ["libhoth_mtd.h"],
    include_prefix = "libhoth/transports",
    strip_include_prefix = ".",
    deps = [
        ":libhoth_device",
        ":libhoth_ec",
    ],
)

cc_library(
    name = "libhoth_mtd_headers_legacy",
    hdrs = ["libhoth_mtd.h"],
    include_prefix = "transports",
    strip_include_prefix = ".",
)

cc_library(
    name = "libhoth_spi",
    srcs = ["libhoth_spi.c"],
    hdrs = ["libhoth_spi.h"],
    include_prefix = "libhoth/transports",
    strip_include_prefix = ".",
    deps = [
        ":libhoth_device",
        ":libhoth_ec",
    ],
)

cc_library(
    name = "libhoth_spi_headers_legacy",
    hdrs = ["libhoth_spi.h"],
    include_prefix = "transports",
    strip_include_prefix = ".",
)

cc_library(
    name = "libhoth_usb",
    srcs = ["libhoth_usb.c"],
    hdrs = ["libhoth_usb.h"],
    include_prefix = "libhoth/transports",
    strip_include_prefix = ".",
    deps = [
        ":libhoth_device",
        ":libhoth_usb_device",
        "//protocol:util",
        "@libusb",
    ],
)

cc_library(
    name = "libhoth_usb_headers_legacy",
    hdrs = [
        "libhoth_usb.h",
        "libhoth_usb_device.h",
    ],
    include_prefix = "transports",
    strip_include_prefix = ".",
)

cc_library(
    name = "libhoth_dbus",
    srcs = ["libhoth_dbus.c"],
    hdrs = ["libhoth_dbus.h"],
    include_prefix = "libhoth/transports",
    strip_include_prefix = ".",
    defines = ["DBUS_BACKEND"],
    linkopts = ["-lsystemd"],
    deps = [":libhoth_device"],
)

cc_library(
    name = "libhoth_dbus_headers_legacy",
    hdrs = ["libhoth_dbus.h"],
    include_prefix = "transports",
    strip_include_prefix = ".",
)

cc_library(
    name = "libhoth_usb_device",
    srcs = [
        "libhoth_usb_fifo.c",
        "libhoth_usb_mailbox.c",
    ],
    hdrs = ["libhoth_usb_device.h"],
    include_prefix = "libhoth/transports",
    strip_include_prefix = ".",
    deps = [
        ":libhoth_device",
        ":libhoth_ec",
        "@libusb",
    ],
)

filegroup(
    name = "headers",
    srcs = glob(["*.h"]),
)
