
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
    "libusb/os/linux_usbfs.h",
    "libusb/os/linux_usbfs.c",
    "libusb/os/linux_netlink.c",
    "libusb/os/threads_posix.h",
    "libusb/os/threads_posix.c",
    "libusb/version.h",
    "libusb/version_nano.h",
  ],
  includes = [
    "libusb",
  ],
  hdrs = [
    "config.h",
    "libusb/libusb.h",
  ],
  copts = ["-isystem", "external/libusb/libusb", "-isystem", "external/libusb"],
  linkopts = ["-lpthread"],
  visibility = ["//visibility:public"],
)

