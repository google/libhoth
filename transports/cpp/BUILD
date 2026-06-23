load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_binary.bzl", "cc_binary")

package(default_visibility = ["//visibility:public"])

CPP23_COPTS = [
    "-std=c++23",
    "-Wa,--gsframe=no",
]

cc_library(
    name = "hoth_device",
    srcs = ["hoth_device.cc"],
    hdrs = ["hoth_device.h"],
    copts = CPP23_COPTS,
    deps = [
        "//transports:libhoth_device",
    ],
)

cc_library(
    name = "usb_hoth_device",
    srcs = ["usb_hoth_device.cc"],
    hdrs = ["usb_hoth_device.h"],
    copts = CPP23_COPTS,
    deps = [
        ":hoth_device",
        "//transports:libhoth_usb",
        "//protocol:util",
    ],
)

cc_library(
    name = "mtd_hoth_device",
    srcs = ["mtd_hoth_device.cc"],
    hdrs = ["mtd_hoth_device.h"],
    copts = CPP23_COPTS,
    deps = [
        ":hoth_device",
        "//transports:libhoth_mtd",
    ],
)

cc_library(
    name = "spi_hoth_device",
    srcs = ["spi_hoth_device.cc"],
    hdrs = ["spi_hoth_device.h"],
    copts = CPP23_COPTS,
    deps = [
        ":hoth_device",
        "//transports:libhoth_spi",
    ],
)

cc_binary(
    name = "transport_test",
    srcs = ["transport_test.cc"],
    copts = CPP23_COPTS,
    deps = [
        ":hoth_device",
        ":usb_hoth_device",
        ":mtd_hoth_device",
        ":spi_hoth_device",
        "//protocol:hello",
        "@libusb",
    ],
)
