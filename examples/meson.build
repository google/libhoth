ecsrcs = ['ec_util.c']
ecutil = library('ec_util', ecsrcs, dependencies: libusb, install: true, \
    version: meson.project_version())

git_version_h = vcs_tag(
  command: ['git', 'describe', '--always', '--dirty', '--abbrev=40'],
  input: 'git_version.h.in',
  output: 'git_version.h',
  replace_string: '@GIT_COMMIT@',
)

link_with = [libhoth]
c_args = []

if get_option('dbus_backend')
  link_with += libhoth_dbus
  c_args += '-DDBUS_BACKEND'
endif

executable(
  'htool',
  sources: [
    'authorization_record.h',
    'authorization_record.c',
    'ec_util.c',
    'htool.c',
    'htool_cmd.c',
    'htool_console.c',
    'htool_dbus.c',
    'htool_i2c.c',
    'htool_mtd.c',
    'htool_panic.c',
    'htool_payload.c',
    'htool_payload_update.c',
    'htool_progress.c',
    'htool_raw_host_command.c',
    'htool_spi.c',
    'htool_spi_proxy.c',
    'htool_statistics.c',
    'htool_target_control.c',
    'htool_usb.c',
    'htool_srtm.h',
    'htool_srtm.c',
    git_version_h],
  dependencies: [libusb],
  link_with: link_with,
  c_args: c_args,
  install: true)
