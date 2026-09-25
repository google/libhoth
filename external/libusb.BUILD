
cc_library(
  name = "libusb",
  srcs = [
    "libusb/core.c",
    "libusb/descriptor.c",
    "libusb/hotplug.c",
    "libusb/io.c",
    "libusb/libusbi.h",
    "libusb/strerror.c",
    "libusb/sync.c",
    "libusb/os/events_posix.h",
    "libusb/os/events_posix.c",
    "libusb/os/threads_posix.h",
    "libusb/os/threads_posix.c",
    "libusb/version.h",
    "libusb/version_nano.h",
  ] + select({
    "@bazel_tools//src/conditions:darwin": [
      "libusb/os/darwin_usb.h",
      "libusb/os/darwin_usb.c",
    ],
    "//conditions:default": [
      "libusb/os/linux_usbfs.h",
      "libusb/os/linux_usbfs.c",
      "libusb/os/linux_netlink.c",
    ],
  }),
  includes = [
    "libusb",
  ],
  hdrs = [
    "config.h",
    "libusb/libusb.h",
  ],
  copts = [
    "-isystem", "external/{}/libusb".format(repo_name()), 
    "-isystem", "external/{}".format(repo_name()),
  ],
  linkopts = select({
    "@bazel_tools//src/conditions:darwin": [
      "-lobjc",
      "-framework", "IOKit",
      "-framework", "CoreFoundation",
      "-framework", "Security",
    ],
    "//conditions:default": [
      "-lpthread",
    ],
  }),
  visibility = ["//visibility:public"],
)
