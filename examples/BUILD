load("@rules_cc//cc:cc_binary.bzl", "cc_binary")

package(default_visibility = ["//visibility:public"])

# Compat: htool moved to //tools/htool:htool. Downstream users still depend on
# //examples:htool as a cc_binary (e.g. its implicit :htool.stripped output)
# and look the binary up at the runfiles path "libhoth/examples/htool", which
# neither an alias nor a genrule provides. Remove once downstream migrates to
# //tools/htool:htool.
cc_binary(
    name = "htool",
    features = ["fully_static_link_target"],
    deps = ["//tools/htool:htool_lib"],
)
