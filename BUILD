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
    name = "libhoth",
    deps = [
        "//transports:libhoth_device",
        "//transports:libhoth_usb",
        "//transports:libhoth_spi",
        "//transports:libhoth_mtd",
    ],
    visibility = ["//visibility:public"],
)

alias(
    name = "libusb",
    actual = "@libusb//:libusb",
    visibility = ["//visibility:public"],
)
