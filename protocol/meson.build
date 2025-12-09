protocol_srcs = [
    'host_cmd.c',
    'rot_firmware_version.c',
    'payload_status.c',
    'panic.c',
    'payload_update.c',
    'statistics.c',
    'reboot.c',
    'chipinfo.c',
    'i2c.c',
    'authz_record.c',
    'progress.c',
    'spi_proxy.c',
    'payload_info.c',
    'controlled_storage.c',
    'jtag.c',
    'hello.c',
    'key_rotation.c',
    'secure_boot.c',
    'command_version.c',
    'dfu_hostcmd.c',
]

incdir = include_directories('..')

libhoth_protocol = static_library(
    'hoth_protocols',
    protocol_srcs,
    include_directories: incdir,
    link_with: [libhoth_transport],
)
libhoth_objs += [libhoth_protocol.extract_all_objects(recursive: false)]

libhoth_protocol_headers = []
foreach s : protocol_srcs
    base_name = s.split('/')[-1]
    header_name = base_name.replace('.c', '.h')
    libhoth_protocol_headers += header_name
endforeach

install_headers(libhoth_protocol_headers, subdir: 'libhoth/protocol')
header_subdirs += 'libhoth/protocol'
