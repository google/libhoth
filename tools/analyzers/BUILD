load("@hedron_compile_commands//:refresh_compile_commands.bzl", "refresh_compile_commands")

# Writes compile_commands.json at the workspace root for clangd. Kept out of
# the root package because hedron_compile_commands is a dev_dependency, which
# modules that depend on libhoth can't load. Run via update-analyzers.sh.
refresh_compile_commands(
    name = "refresh_compile_commands",
    tags = ["manual"],
    targets = {
        "//...": "",
    },
)
