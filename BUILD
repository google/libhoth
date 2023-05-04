package(default_visibility = ["//visibility:public"])

cc_library(
    name = "libhoth",
    srcs = [
        "libhoth.c",
        "libhoth_spi.c",
        "libhoth_usb.c",
        "libhoth_usb_fifo.c",
        "libhoth_usb_mailbox.c",
    ],
    hdrs = [
        "libhoth.h",
        "libhoth_ec.h",
        "libhoth_spi.h",
        "libhoth_usb.h",
        "libhoth_usb_device.h",
    ],
    deps = ["@libusb//:libusb"],
)
