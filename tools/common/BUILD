load("@rules_cc//cc:cc_library.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

# Command-line framework shared by host tools. Not part of the libhoth API.
cc_library(
    name = "htool_cmd",
    srcs = ["htool_cmd.c"],
    hdrs = ["htool_cmd.h"],
    deps = ["//:git_version"],
)

cc_library(
    name = "macros",
    hdrs = ["macros.h"],
)
