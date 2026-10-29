#!/bin/zsh

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR"

/opt/homebrew/bin/node ./node_modules/vite/bin/vite.js
