load("@rules_cc//cc:cc_library.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "git_version",
    hdrs = [":gen_version_header"],
)

cc_library(
    name = "libhoth_status",
    hdrs = ["include/libhoth/status.h"],
    strip_include_prefix = "include",
    visibility = ["//visibility:public"],
)


genrule(
    name = "gen_version_header",
    outs = ["git_version.h"],
    cmd = "$(location :print_version_header.sh) > \"$@\"",
    stamp = 1,
    tools = [":print_version_header.sh"],
)
