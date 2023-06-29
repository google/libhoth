package(
    default_applicable_licenses = ["//third_party/libhoth:license"],
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "libhoth",
    srcs = [
        "libhoth.c",
        "libhoth_mtd.c",
        "libhoth_spi.c",
        "libhoth_usb.c",
        "libhoth_usb_fifo.c",
        "libhoth_usb_mailbox.c",
    ],
    hdrs = [
        "libhoth.h",
        "libhoth_ec.h",
        "libhoth_mtd.h",
        "libhoth_spi.h",
        "libhoth_usb.h",
        "libhoth_usb_device.h",
    ],
    deps = ["@libusb//:libusb"],
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

