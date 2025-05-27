#!/bin/sh

# https://bazel.build/docs/user-manual#workspace-status
#
# Custom script to obtain the STABLE_GIT_COMMIT variable
# from bazel and generate a header file that defines the
# value.

git_commit=$(sed -nE 's/^STABLE_GIT_COMMIT ([a-z0-9\-]+)$/\1/p' bazel-out/stable-status.txt)

if [ -z "$git_commit" ]; then
  >&2 echo "failed to parse Git commit"
  exit 1
fi

header="
#ifndef LIBHOTH_EXAMPLES_HTOOL_VERSION_H_
#define LIBHOTH_EXAMPLES_HTOOL_VERSION_H_

#define STABLE_GIT_COMMIT \"$git_commit\" 

#endif
"

echo "$header"
