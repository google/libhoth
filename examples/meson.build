git_version_h = vcs_tag(
    command: ['git', 'describe', '--always', '--dirty', '--abbrev=40'],
    input: 'git_version.h.in',
    output: 'git_version.h',
    replace_string: '@GIT_COMMIT@',
)

incdir = include_directories('..')
link_with = [libhoth.get_static_lib()]
c_args = []

if get_option('dbus_backend')
    link_with += libhoth_dbus
    c_args += '-DDBUS_BACKEND'
endif

executable(
    'htool',
    sources: [
        'htool.c',
        'htool_authz_command.c',
        'htool_cmd.c',
        'htool_console.c',
        'htool_dbus.c',
        'htool_i2c.c',
        'htool_jtag.c',
        'htool_mtd.c',
        'htool_key_rotation.c',
        'htool_panic.c',
        'htool_payload.c',
        'htool_payload_update.c',
        'htool_raw_host_command.c',
        'htool_rot_usb.c',
        'htool_spi.c',
        'htool_statistics.c',
        'htool_target_control.c',
        'htool_usb.c',
        'htool_secure_boot.h',
        'htool_secure_boot.c',
        'htool_srtm.h',
        'htool_srtm.c',
        'htool_security_version.h',
        'htool_security_version.c',
        'htool_security_v2.h',
        'htool_security_v2.c',
        'htool_macros.h',
        'htool_security_info.h',
        'htool_security_info.c',
        git_version_h,
    ],
    dependencies: [libusb],
    link_with: link_with,
    include_directories: incdir,
    c_args: c_args,
    install: true,
)
