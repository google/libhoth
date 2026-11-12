# Backward-compatibility aliases for the move of //protocol to //host/protocol.
# Do not depend on these from within libhoth. They will be removed once
# downstream consumers have migrated to //host/protocol.

package(default_visibility = ["//visibility:public"])

_DEPRECATION = "Moved to //host/protocol; this alias will be removed."

[
    alias(
        name = name,
        actual = "//host/protocol:" + name,
        deprecation = _DEPRECATION,
    )
    for name in [
        "authz_record",
        "chipinfo",
        "command_version",
        "console",
        "controlled_storage",
        "dfu_check",
        "dfu_hostcmd",
        "firmware_update",
        "gpio_drive_strength",
        "hello",
        "host_cmd",
        "i2c",
        "jtag",
        "key_rotation",
        "libhoth_status",
        "mauv",
        "opentitan_version",
        "panic",
        "payload_info",
        "payload_status",
        "payload_update",
        "progress",
        "provisioning",
        "reboot",
        "rot_firmware_version",
        "secure_boot",
        "spi_proxy",
        "statistics",
        "target_watchdog",
        "update_session",
        "util",
    ]
]
