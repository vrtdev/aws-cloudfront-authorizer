#!/usr/bin/env bash

# Usage: ./build.sh <directory-to-package> <ZIP-file-to-create>
#
#  Defaults:
#    src/ -> build.zip


set -o errexit
set -o pipefail
set -o nounset
#set -o xtrace

SRC_DIR="${1:-src}"
OUT_FILE="${2:-build.zip}"

# make OUT_FILE absolute
case "${OUT_FILE}" in
    /*) ;;  # already absolute path
    *) OUT_FILE="${PWD}/${OUT_FILE}";;
esac

# make sure the file is empty. Zip will *add* if the file exists
rm -f "${OUT_FILE}"

BUILD_DIR=`mktemp -d 2>/dev/null || mktemp -d -t 'build'`  # Linux & BSD-compatible

cp -a "${SRC_DIR}/" "${BUILD_DIR}"

# Possibly re-use venv from ./test.sh
if [ ! -f "venv/bin/pip" ]; then
    # create venv only if not already there
    python3 -m venv venv
fi
venv/bin/pip install -r "${SRC_DIR}/requirements.txt" -t "${BUILD_DIR}"

(
    cd "${BUILD_DIR}"
    rm "requirements.txt"
    find . -name '__pycache__' -prune -exec rm -rf '{}' ';'
    zip "${OUT_FILE}" -r .
)
