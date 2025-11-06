#!/usr/bin/env sh
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
ROOT="$(dirname "$(dirname "$(dirname "$(readlink -f "$0")")")")"

APP_NAME="cursor"
VERSION="1.7.38"
COMMIT="fe5d1728063e86edeeda5bebd2c8e14bf4d0f960"
EXEC_NAME="cursor"
CLI_SCRIPT="$ROOT/out/server-cli.js"
"$ROOT/node" "$CLI_SCRIPT" "$APP_NAME" "$VERSION" "$COMMIT" "$EXEC_NAME" "--openExternal" "$@"
