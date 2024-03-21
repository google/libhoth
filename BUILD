package(default_visibility = ["//visibility:public"])

cc_library(
    name = "libhoth",
    srcs = ["libhoth.c"],
    hdrs = ["libhoth.h"],
)

cc_library(
    name = "git_version",
    hdrs = [":gen_version_header"],
)

genrule(
    name = "gen_version_header",
    outs = ["git_version.h"],
    cmd = "$(location :print_version_header.sh) > \"$@\"",
    tools = [":print_version_header.sh"],
    stamp = 1,
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
        ":libhoth",
        ":libhoth_ec",
    ],
)

cc_library(
    name = "libhoth_spi",
    srcs = ["libhoth_spi.c"],
    hdrs = ["libhoth_spi.h"],
    deps = [
        ":libhoth",
        ":libhoth_ec",
    ],
)

cc_library(
    name = "libhoth_usb",
    srcs = ["libhoth_usb.c"],
    hdrs = ["libhoth_usb.h"],
    deps = [
        ":libhoth",
        ":libhoth_usb_device",
        "@libusb//:libusb",
    ],
)

cc_library(
    name = "libhoth_dbus",
    srcs = ["libhoth_dbus.c"],
    hdrs = ["libhoth_dbus.h"],
    linkopts = ["-lsystemd"],
    defines = ["DBUS_BACKEND"],
    deps = [
        ":libhoth",
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
        ":libhoth",
        ":libhoth_ec",
        "@libusb//:libusb",
    ],
)
