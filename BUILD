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
    name = "libhoth_transports_headers",
    hdrs = [
        "//host/transports:headers",
    ],
    include_prefix = "libhoth/transports",
    strip_include_prefix = "host/transports",
)

cc_library(
    name = "libhoth_transports_headers_legacy",
    hdrs = [
        "//host/transports:headers",
    ],
    include_prefix = "transports",
    strip_include_prefix = "host/transports",
)

cc_library(
    name = "libhoth",
    visibility = ["//visibility:public"],
    deps = [
        ":libhoth_transports_headers",
        ":libhoth_transports_headers_legacy",
        "//host/transports:libhoth_device",
        "//host/transports:libhoth_mtd",
        "//host/transports:libhoth_spi",
        "//host/transports:libhoth_usb",
    ],
)

alias(
    name = "libusb",
    actual = "@libusb//:libusb",
    visibility = ["//visibility:public"],
)
