package(default_visibility = ["//visibility:public"])

cc_library(
    name = "host_commands",
    textual_hdrs = [
        "host_commands.h",
    ],
)

cc_library(
    name = "ec_util",
    srcs = [
        "ec_util.c",
    ],
    hdrs = ["ec_util.h"],
    deps = [":host_commands"],
)

cc_binary(
    name = "htool",
    srcs = [
        "ec_util.c",
        "ec_util.h",
        "host_commands.h",
        "htool.c",
        "htool.h",
        "htool_cmd.c",
        "htool_cmd.h",
        "htool_console.c",
        "htool_console.h",
        "htool_mtd.c",
        "htool_progress.c",
        "htool_progress.h",
        "htool_spi.c",
        "htool_spi_proxy.c",
        "htool_spi_proxy.h",
        "htool_usb.c",
        "htool_usb.h",
    ],
    deps = [
        ":ec_util",
        ":host_commands",
        "//:libhoth",
        "@libusb//:libusb",
    ],
)
