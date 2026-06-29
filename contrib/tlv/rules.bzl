# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Bazel rules for Protobuf-to-TLV code generation."""

load("@protobuf//bazel/common:proto_info.bzl", "ProtoInfo")
load("@rules_rust//rust:defs.bzl", "rust_library")

def _tlv_codegen_rule_impl(ctx):
    # Declare the output Rust file
    output_file = ctx.actions.declare_file(ctx.label.name + ".rs")

    # Collect all transitive descriptor set files from the proto dependency
    proto_info = ctx.attr.proto[ProtoInfo]
    descriptor_sets = proto_info.transitive_descriptor_sets.to_list()

    # Get the rustfmt toolchain
    rustfmt_toolchain = ctx.toolchains["@rules_rust//rust/rustfmt:toolchain_type"]

    # Build the arguments for the codegen tool
    args = ctx.actions.args()
    for ds in descriptor_sets:
        args.add("--descriptor-set", ds.path)
    args.add("--output", output_file.path)
    if ctx.attr.test_label:
        args.add("--test-label", ctx.attr.test_label)

    # Run the codegen tool
    ctx.actions.run(
        outputs = [output_file],
        inputs = depset(
            direct = descriptor_sets,
            transitive = [rustfmt_toolchain.all_files],
        ),
        executable = ctx.executable._codegen_tool,
        arguments = [args],
        env = {
            "RUSTFMT": rustfmt_toolchain.rustfmt.path,
        },
        mnemonic = "TlvCodegen",
        progress_message = "Generating and formatting TLV Rust structs for %{label}",
    )

    # Return the generated file
    return [
        DefaultInfo(files = depset([output_file])),
    ]

_tlv_codegen_rule = rule(
    implementation = _tlv_codegen_rule_impl,
    attrs = {
        "proto": attr.label(
            mandatory = True,
            providers = [ProtoInfo],
            doc = "The proto_library target to generate TLV structs for.",
        ),
        "_codegen_tool": attr.label(
            default = Label("//contrib/tlv:codegen"),
            executable = True,
            cfg = "exec",
        ),
        "test_label": attr.string(
            doc = "The label of the diff test target if a checked-in source is used.",
        ),
    },
    toolchains = ["@rules_rust//rust/rustfmt:toolchain_type"],
    doc = "Generates zero-copy Rust TLV structs from a proto_library.",
)

def _update_golden_impl(ctx):
    file_a = ctx.file.file_a
    file_b = ctx.file.file_b
    script = ctx.actions.declare_file(ctx.label.name + "_update.sh")

    content = """#!/bin/bash
FILE_A="{file_a_path}"
FILE_B="{file_b_path}"

if [ -z "$BUILD_WORKSPACE_DIRECTORY" ]; then
    echo "Error: This target must be run using 'bazel run'." >&2
    exit 1
fi

DEST="$BUILD_WORKSPACE_DIRECTORY/$FILE_A"
echo "Updating checked-in file: $DEST"
cp "$FILE_B" "$DEST"
chmod +w "$DEST"
""".format(
        file_a_path = file_a.short_path,
        file_b_path = file_b.short_path,
    )

    ctx.actions.write(
        output = script,
        content = content,
        is_executable = True,
    )

    return [
        DefaultInfo(
            executable = script,
            runfiles = ctx.runfiles(files = [file_a, file_b]),
        ),
    ]

_update_golden = rule(
    implementation = _update_golden_impl,
    attrs = {
        "file_a": attr.label(allow_single_file = True, mandatory = True),
        "file_b": attr.label(allow_single_file = True, mandatory = True),
    },
    executable = True,
    doc = "Copies a generated file back to the source tree when executed via 'bazel run'.",
)

def tlv_codegen(name, proto, src = None, visibility = None, **kwargs):
    """Generates a first-class Rust crate containing TLV structs from a proto_library.

    If `src` is specified, it compiles the checked-in file directly and defines a companion
    update binary target named `<name>_update` to ensure the checked-in file can be updated.

    Args:
        name: The name of the generated rust_library target.
        proto: The proto_library target to generate structs for.
        src: Optional checked-in Rust source file.
        visibility: The visibility of the target.
        **kwargs: Additional arguments passed to the underlying rust_library.
    """
    gen_file_target = name + "_gen_file"

    # 1. Define the action to generate the .rs source file
    _tlv_codegen_rule(
        name = gen_file_target,
        proto = proto,
        test_label = "//{}:{}_update".format(native.package_name(), name) if src else None,
        visibility = ["//visibility:private"],
    )

    # 2. Compile the rust_library (using either checked-in src or generated file)
    rust_src = src if src else ":" + gen_file_target

    compile_data = kwargs.pop("compile_data", [])
    if src:
        verified_src_target = name + "_verified_src"
        native.genrule(
            name = verified_src_target,
            srcs = [src, ":" + gen_file_target],
            outs = [name + "_verified.txt"],
            cmd = """
            if ! diff -u $(location {src}) $(location :{gen}); then
                echo "" >&2
                echo "================================================================================" >&2
                echo "Error: Checked-in file '$(location {src})' does not match the generated contents." >&2
                echo "To automatically update the checked-in file, run:" >&2
                echo "    bazel run //{package}:{name}_update" >&2
                echo "================================================================================" >&2
                exit 1
            fi
            touch $@
            """.format(
                src = src,
                gen = gen_file_target,
                package = native.package_name(),
                name = name,
            ),
            visibility = ["//visibility:private"],
        )

        # Force dependency on the verification genrule at build-time, preserving perfect IDE support on `src`
        compile_data = compile_data + [":" + verified_src_target]

    tags = kwargs.get("tags", [])
    for t in ["no-format", "no-rustfmt", "norustfmt", "no-clippy"]:
        if t not in tags:
            tags.append(t)
    kwargs["tags"] = tags

    rust_library(
        name = name,
        srcs = [rust_src],
        crate_name = name,
        edition = "2024",
        visibility = visibility,
        compile_data = compile_data,
        deps = [
            "//contrib/tlv",
            "//third_party:zerocopy",
            "//types",
        ],
        proc_macro_deps = [
            "//third_party:bitfield_struct",
        ],
        **kwargs
    )

    # 3. If checked-in src is used, define a companion update target
    if src:
        _update_golden(
            name = name + "_update",
            file_a = src,
            file_b = ":" + gen_file_target,
            visibility = visibility,
        )
