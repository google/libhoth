ecsrcs = ['ec_util.c']
ecutil = library('ec_util', ecsrcs, dependencies: libusb, install: true, \
    version: meson.project_version())

executable(
  'htool',
  sources: [
    'ec_util.c',
    'htool.c',
    'htool_cmd.c',
    'htool_console.c',
    'htool_mtd.c',
    'htool_progress.c',
    'htool_spi.c',
    'htool_spi_proxy.c',
    'htool_usb.c'],
  implicit_include_directories: false,
  dependencies: [libusb],
  link_with: [libhoth],
  install: true)
