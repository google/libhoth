project('libhoth', 'c', 'cpp', license: 'Apache-2.0', version: '0.0.0')

libhoth_srcs = [
  'libhoth.c',
  'libhoth_mtd.c',
  'libhoth_usb.c',
  'libhoth_spi.c',
  'libhoth_usb_fifo.c',
  'libhoth_usb_mailbox.c',
  'libhoth_dbus.c',
]
libusb = dependency('libusb-1.0')
libsystemd = dependency('libsystemd')
libhoth = library('hoth', libhoth_srcs, dependencies: [libusb, libsystemd], install: true, \
    version: meson.project_version())
install_headers('libhoth.h')
install_headers('libhoth_usb.h')
install_headers('libhoth_usb_device.h')

pkg = import('pkgconfig')
pkg.generate(libhoth, name: 'libhoth', description: 'Hoth interface library')

subdir('examples')
