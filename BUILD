package(default_visibility = ["//visibility:public"])

cc_library(
    name = "libhoth_usb",
    srcs = [
        "libhoth_usb.c",
        "libhoth_usb_device.h",
        "libhoth_usb_fifo.c",
        "libhoth_usb_mailbox.c",
    ],
    hdrs = ["libhoth_usb.h"],
    linkopts = ["-lusb-1.0"],
)
