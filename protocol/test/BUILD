# Backward-compatibility targets for the move of //protocol/test to
# //host/protocol/test. Will be removed once downstream consumers migrate.

package(default_visibility = ["//visibility:public"])

alias(
    name = "libhoth_device_mock",
    actual = "//host/protocol/test:libhoth_device_mock",
    deprecation = "Moved to //host/protocol/test; this alias will be removed.",
)

# Re-materialize the fixtures under this package so their runfiles paths stay
# at protocol/test/<name>.bin for existing consumers.
genrule(
    name = "compat_test_data_copy",
    srcs = ["//host/protocol/test:test_data"],
    outs = [
        "panic_record.bin",
        "test_fwupdate.bin",
        "test_fwupdate_88k.bin",
        "test_payload.bin",
    ],
    cmd = "for f in $(SRCS); do cp \"$$f\" \"$(@D)/$$(basename \"$$f\")\"; done",
)

filegroup(
    name = "test_data",
    srcs = [":compat_test_data_copy"],
)
