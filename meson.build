project('libhoth', 'c', 'cpp', license: 'Apache-2.0', version: '0.0.0')

subdir('transports')
subdir('protocol')

install_headers('transports/libhoth_device.h')
install_headers('transports/libhoth_spi.h')
install_headers('transports/libhoth_usb.h')
install_headers('transports/libhoth_usb_device.h')

libhoth = library('hoth', [], link_with: [libhoth_transport, libhoth_protocol], dependencies: [libusb], \
    version: meson.project_version())

pkg = import('pkgconfig')
pkg.generate([libhoth], name: 'libhoth', description: 'Hoth interface library')

subdir('examples')
