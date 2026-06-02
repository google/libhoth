load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

def _libusb_extension_impl(ctx):
    git_repository(
        name = "libusb",
        build_file = "@libhoth//:external/libusb.BUILD",
        commit = "4239bc3a50014b8e6a5a2a59df1fff3b7469543b",
        remote = "https://github.com/libusb/libusb",
        patches = ["@libhoth//:external/libusb.patch"],
        shallow_since = "1649581036 +0200",
    )

libusb_extension = module_extension(
    implementation = _libusb_extension_impl,
)
