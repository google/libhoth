ecsrcs = ['ec_util.c']
ecutil = library('ec_util', ecsrcs, dependencies: libusb, install: true, \
    version: meson.project_version())

git_version_h = vcs_tag(
  command: ['git', 'describe', '--always', '--dirty', '--abbrev=40'],
  input: 'git_version.h.in',
  output: 'git_version.h',
  replace_string: '@GIT_COMMIT@',
)

executable(
  'htool',
  sources: [
    'authorization_record.h',
    'authorization_record.c',
    'ec_util.c',
    'htool.c',
    'htool_cmd.c',
    'htool_console.c',
    'htool_mtd.c',
    'htool_panic.c',
    'htool_payload.c',
    'htool_payload_update.c',
    'htool_progress.c',
    'htool_raw_host_command.c',
    'htool_spi.c',
    'htool_spi_proxy.c',
    'htool_statistics.c',
    'htool_usb.c',
    git_version_h],
  dependencies: [libusb],
  link_with: [libhoth],
  install: true)
