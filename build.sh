#!/usr/bin/env bash

# Usage: ./build.sh <ZIP-file-to-create>


set -o errexit
set -o pipefail
set -o nounset
#set -o xtrace

OUT_FILE="${1:-build.zip}"

# make OUT_FILE absolute
case "${OUT_FILE}" in
    /*) ;;  # already absolute path
    *) OUT_FILE="${PWD}/${OUT_FILE}";;
esac

# make sure the file is empty. Zip will *add* if the file exists
rm -f "${OUT_FILE}"

rm -rf build
cp -a src build

# Possibly re-use venv from ./test.sh
if [ ! -f "venv/bin/pip" ]; then
    # create venv only if not already there
    python3 -m venv venv
fi
venv/bin/pip install -r src/requirements.txt -t build

(
    cd build
    find . -name '__pycache__' -prune -exec rm -rf '{}' ';'
    zip "${OUT_FILE}" -r .
)
