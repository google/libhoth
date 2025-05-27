#!/bin/sh

# https://bazel.build/docs/user-manual#workspace-status
#
# Custom script to generate the STABLE_GIT_COMMIT variable
# used by other tooling.

# Try git first
commit=$(git describe --always --dirty --abbrev=40 2>/dev/null)
if [ $? -eq 0 ]; then
  echo "STABLE_GIT_COMMIT git-$commit"
  exit 0
fi

# git failed, try jj (https://jj-vcs.github.io/)
changeid=$(jj show -T change_id --no-patch 2>/dev/null)
if [ $? -eq 0 ]; then
  echo "STABLE_GIT_COMMIT jj-$changeid"
  exit 0
fi

# None worked
>&2 echo "failed to get commit/change revision"
exit 1
