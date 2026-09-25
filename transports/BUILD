load("@rules_cc//cc:cc_library.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "libhoth_device",
    srcs = ["libhoth_device.c"],
    hdrs = ["libhoth_device.h"],
    deps = [
        "//protocol:libhoth_status",
    ],
)

cc_library(
    name = "libhoth_ec",
    hdrs = ["libhoth_ec.h"],
)

config_setting(
    name = "dbus_backend",
    define_values = {
        "dbus_backend": "true",
    },
)

config_setting(
    name = "mtd_backend",
    define_values = {
        "mtd_backend": "true",
    },
)

config_setting(
    name = "spi_backend",
    define_values = {
        "spi_backend": "true",
    },
)

cc_library(
    name = "libhoth_mtd",
    srcs = ["libhoth_mtd.c"],
    hdrs = ["libhoth_mtd.h"],
    defines = ["MTD_BACKEND"],
    target_compatible_with = ["@platforms//os:linux"],
    deps = [
        ":libhoth_device",
        ":libhoth_ec",
        "//protocol:libhoth_status",
    ],
)

cc_library(
    name = "libhoth_spi",
    srcs = ["libhoth_spi.c"],
    hdrs = ["libhoth_spi.h"],
    defines = ["SPI_BACKEND"],
    target_compatible_with = ["@platforms//os:linux"],
    deps = [
        ":libhoth_device",
        ":libhoth_ec",
        "//protocol:libhoth_status",
    ],
)

cc_library(
    name = "libhoth_usb",
    srcs = ["libhoth_usb.c"],
    hdrs = ["libhoth_usb.h"],
    deps = [
        ":libhoth_device",
        ":libhoth_usb_device",
        "//protocol:libhoth_status",
        "//protocol:util",
        "@libusb",
    ],
)

cc_library(
    name = "libhoth_dbus",
    srcs = ["libhoth_dbus.c"],
    hdrs = ["libhoth_dbus.h"],
    defines = ["DBUS_BACKEND"],
    linkopts = ["-lsystemd"],
    target_compatible_with = ["@platforms//os:linux"],
    deps = [
        ":libhoth_device",
        "//protocol:libhoth_status",
    ],
)

cc_library(
    name = "libhoth_usb_device",
    srcs = [
        "libhoth_usb_fifo.c",
        "libhoth_usb_mailbox.c",
    ],
    hdrs = ["libhoth_usb_device.h"],
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
