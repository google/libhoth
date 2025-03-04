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
]

incdir = include_directories('..')

libhoth_protocol = library('hoth_protocols', protocol_srcs, include_directories: incdir, link_with: [libhoth_transport])
