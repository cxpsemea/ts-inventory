#!/bin/bash

pushd $(dirname "$0")

# -----------------------------
# Create cxinventory executable
# -----------------------------
pyinstaller --clean --noconfirm --onefile --nowindow --distpath=../.dist/cxinventory/ubuntu --workpath=temp --paths=../shared ../cxinventory/cxinventory.py
cp ../cxinventory/src/cxinventoryconfig.yaml ../.dist/cxinventory/ubuntu/config.yaml
cp ../LICENSE ../.dist/cxinventory/ubuntu/LICENSE
rm -f -r --interactive=never cxinventory.spec
rm -f -r --interactive=never temp
tar -czvf ../.dist/cxinventory-ubuntu64.tar.gz -C ../.dist/cxinventory/ubuntu .

popd
