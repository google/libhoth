# Backward-compatibility aliases for the move of //transports to //host/transports.
# Do not depend on these from within libhoth. They will be removed once
# downstream consumers have migrated to //host/transports.

package(default_visibility = ["//visibility:public"])

_DEPRECATION = "Moved to //host/transports; this alias will be removed."

[
    alias(
        name = name,
        actual = "//host/transports:" + name,
        deprecation = _DEPRECATION,
    )
    for name in [
        "headers",
        "libhoth_dbus",
        "libhoth_device",
        "libhoth_ec",
        "libhoth_mtd",
        "libhoth_spi",
        "libhoth_usb",
        "libhoth_usb_device",
    ]
]
