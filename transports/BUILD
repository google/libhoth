load("@rules_cc//cc:cc_library.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "libhoth_device",
    srcs = ["libhoth_device.c"],
    hdrs = ["libhoth_device.h"],
)

cc_library(
    name = "libhoth_ec",
    hdrs = ["libhoth_ec.h"],
)

cc_library(
    name = "libhoth_mtd",
    srcs = ["libhoth_mtd.c"],
    hdrs = ["libhoth_mtd.h"],
    deps = [
        ":libhoth_device",
        ":libhoth_ec",
    ],
)

cc_library(
    name = "libhoth_spi",
    srcs = ["libhoth_spi.c"],
    hdrs = ["libhoth_spi.h"],
    deps = [
        ":libhoth_device",
        ":libhoth_ec",
    ],
)

cc_library(
    name = "libhoth_usb",
    srcs = ["libhoth_usb.c"],
    hdrs = ["libhoth_usb.h"],
    deps = [
        ":libhoth_device",
        ":libhoth_usb_device",
        "@libusb",
    ],
)

cc_library(
    name = "libhoth_dbus",
    srcs = ["libhoth_dbus.c"],
    hdrs = ["libhoth_dbus.h"],
    defines = ["DBUS_BACKEND"],
    linkopts = ["-lsystemd"],
    deps = [":libhoth_device"],
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
