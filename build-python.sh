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
HASH_FILE="${3:-}"

make_absolute() {
    if [ -z "${1}" ]; then
        return
    fi
    case "${1}" in
        /*) echo "${1}";;  # already absolute path
        *)  echo "${PWD}/${1}";;
    esac
}

OUT_FILE="$( make_absolute "${OUT_FILE}" )"
HASH_FILE="$( make_absolute "${HASH_FILE}" )"

# make sure the file is empty. Zip will *add* if the file exists
rm -f "${OUT_FILE}"

BUILD_DIR=`mktemp -d 2>/dev/null || mktemp -d -t 'build'`  # Linux & BSD-compatible

cp -a "${SRC_DIR}/." "${BUILD_DIR}"

# Possibly re-use venv from ./test.sh
if [ ! -f "venv/bin/pip" ]; then
    # create venv only if not already there
    python3 -m venv venv
fi

# make sure build tools are up to date
venv/bin/pip install --upgrade wheel pip
venv/bin/pip install -r "${SRC_DIR}/requirements.txt" -t "${BUILD_DIR}"

(
    cd "${BUILD_DIR}"
    rm "requirements.txt"
    find . -name '__pycache__' -prune -exec rm -rf '{}' ';'

    if [ -n "${HASH_FILE}" ]; then
        git init -q
        git add --all
        git commit --no-gpg-sign -qm 'whatever'
        git cat-file -p HEAD | grep '^tree' | awk '{print $2}' > "${HASH_FILE}"
        echo "Content hash: $(< "${HASH_FILE}" )"
        rm -rf .git
    fi

    zip "${OUT_FILE}" -r .
)
