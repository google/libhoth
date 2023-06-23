#!/bin/sh

# https://bazel.build/docs/user-manual#workspace-status

if ! commit=$(git describe --always --dirty --abbrev=40); then
  >&2 echo "failed to get SHA-1 of HEAD"
  exit 1
fi

echo "STABLE_GIT_COMMIT $commit"

