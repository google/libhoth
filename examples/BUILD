
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
    name = "enumerate",
    srcs = [
        "bind.c",
        "bind.h",
        "enumerate.c",
    ],
    linkopts = ["-lusb-1.0"],
    deps = ["//:libhoth_usb"],
)

cc_binary(
    name = "ec_hello",
    srcs = [
        "bind.c",
        "bind.h",
        "ec_hello.c",
    ],
    linkopts = ["-lusb-1.0"],
    deps = [
        ":ec_util",
        ":host_commands",
        "//:libhoth_usb",
    ],
)

cc_binary(
    name = "htool",
    srcs = [
        "ec_util.c",
        "ec_util.h",
        "host_commands.h",
        "htool.c",
        "htool_cmd.c",
        "htool_cmd.h",
        "htool_console.c",
        "htool_console.h",
        "htool_progress.c",
        "htool_progress.h",
        "htool_spi.c",
        "htool_spi.h",
        "htool_usb.c",
        "htool_usb.h",
    ],
    deps = [
        "//:libhoth_usb",
    ],
)
