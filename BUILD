package(default_visibility = ["//visibility:public"])

cc_library(
    name = "git_version",
    hdrs = [":gen_version_header"],
)

genrule(
    name = "gen_version_header",
    outs = ["git_version.h"],
    cmd = "$(location :print_version_header.sh) > \"$@\"",
    tools = [":print_version_header.sh"],
    stamp = 1,
)
