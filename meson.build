project('libhoth', 'c', 'cpp', license: 'Apache-2.0', version: '0.0.0')

subdir('transports')

install_headers('transports/libhoth_device.h')
install_headers('transports/libhoth_usb.h')
install_headers('transports/libhoth_usb_device.h')
install_headers('libhoth.h')

libhoth = library('hoth', ['libhoth.c'], link_with: [libhoth_transport], dependencies: [libusb], \
    version: meson.project_version())

pkg = import('pkgconfig')
pkg.generate([libhoth], name: 'libhoth', description: 'Hoth interface library')

subdir('examples')
