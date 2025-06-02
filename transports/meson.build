transport_srcs = [
    'libhoth_device.c',
    'libhoth_mtd.c',
    'libhoth_usb.c',
    'libhoth_spi.c',
    'libhoth_usb_fifo.c',
    'libhoth_usb_mailbox.c',
]

incdir = include_directories('..')
libusb = dependency('libusb-1.0')
libsystemd = dependency('libsystemd')

if get_option('dbus_backend')
    libhoth_dbus = static_library(
        'hoth_dbus',
        'libhoth_dbus.c',
        include_directories: incdir,
        dependencies: [libsystemd],
        install: true,
    )
    install_headers(['libhoth_dbus.h'], subdir: 'transports')
endif

libhoth_transport = static_library(
    'hoth_transports',
    transport_srcs,
    include_directories: incdir,
    dependencies: [libusb],
)

libhoth_transport_headers = [
    'libhoth_device.h',
    'libhoth_ec.h',
    'libhoth_mtd.h',
    'libhoth_spi.h',
    'libhoth_usb.h',
    'libhoth_usb_device.h',
]
install_headers(libhoth_transport_headers, subdir: 'libhoth/transports')

install_symlink(
    'libhoth.h',
    install_dir: get_option('includedir') / 'libhoth/transports',
    pointing_to: 'libhoth_device.h',
)
header_subdirs += 'libhoth/transports'
