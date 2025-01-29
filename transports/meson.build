transport_srcs = [
  'libhoth_device.c',
  'libhoth_mtd.c',
  'libhoth_usb.c',
  'libhoth_spi.c',
  'libhoth_usb_fifo.c',
  'libhoth_usb_mailbox.c',
]

libusb = dependency('libusb-1.0')
libsystemd = dependency('libsystemd')
libhoth_dbus = static_library('hoth_dbus', 'libhoth_dbus.c', dependencies: [libsystemd])
libhoth_transport = static_library('hoth_transports', transport_srcs, dependencies: [libusb])

