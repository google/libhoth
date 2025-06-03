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
libcap = dependency('libcap')

if get_option('dbus_backend')
    libhoth_dbus = static_library(
        'hoth_dbus',
        'libhoth_dbus.c',
        include_directories: incdir,
        dependencies: [libsystemd],
    )
    libhoth_objs += [libhoth_dbus.extract_all_objects(recursive: false)]
    libhoth_deps += [libsystemd, libcap]
    install_headers(['libhoth_dbus.h'], subdir: 'libhoth/transports')
endif

libhoth_transport = static_library(
    'hoth_transports',
    transport_srcs,
    include_directories: incdir,
    dependencies: [libusb],
)

libhoth_objs += [libhoth_transport.extract_all_objects(recursive: false)]
libhoth_deps += [libusb]

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
