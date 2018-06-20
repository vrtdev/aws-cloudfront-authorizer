#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset
#set -o xtrace

python3 -m venv venv
# don't activate the venv. the activate script fails with `nounset` enabled

venv/bin/pip install -r requirements.txt
venv/bin/pip install -r test-requirements.txt

venv/bin/python -m pytest -v
