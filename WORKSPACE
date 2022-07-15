
load(
    "@bazel_tools//tools/build_defs/repo:git.bzl",
    "new_git_repository",
)

new_git_repository(
    name = "libusb",
    build_file = "libusb.BUILD",
    commit = "4239bc3a50014b8e6a5a2a59df1fff3b7469543b",
    remote = "https://github.com/libusb/libusb",
    patches = ["libusb.patch"],
    shallow_since = "1649581036 +0200",
)

