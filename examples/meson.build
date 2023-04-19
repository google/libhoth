ecsrcs = ['ec_util.c']
ecutil = library('ec_util', ecsrcs, dependencies: libusb, install: true, \
    version: meson.project_version())

executable(
  'htool',
  sources: ['htool.c', 'htool_cmd.c', 'htool_console.c', 'htool_progress.c', 'htool_spi.c', 'htool_spi_proxy.c', 'htool_usb.c', 'ec_util.c'],
  implicit_include_directories: false,
  dependencies: [libusb],
  link_with: [libhoth],
  install: true)
