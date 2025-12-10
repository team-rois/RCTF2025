#!/usr/bin/env sh
set -eu

if ! grep -q "host:" /koishi/koishi.yml; then
  sed -Ei 's/(([[:space:]]*)maxPort.*)/\1\n\2host: 0.0.0.0/' /koishi/koishi.yml
fi

exec "$@"
