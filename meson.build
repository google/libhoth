project('libhoth', 'c', 'cpp', license: 'Apache-2.0', version: '0.0.0')

libhoth_usb_srcs = ['libhoth_usb.c', 'libhoth_usb_fifo.c', 'libhoth_usb_mailbox.c']
libusb = dependency('libusb-1.0')
libhoth_usb = library('hoth_usb', libhoth_usb_srcs, dependencies: libusb, install: true, \
    version: meson.project_version())
install_headers('libhoth_usb.h')

pkg = import('pkgconfig')
pkg.generate(libhoth_usb, name: 'libhoth_usb', description: 'Hoth USB interface library')

subdir('examples')
