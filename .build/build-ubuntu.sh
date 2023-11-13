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

# -------------------------------
# Create cxquerymerger executable
# -------------------------------
pyinstaller --clean --noconfirm --onefile --nowindow --distpath=../.dist/cxquerymerger/ubuntu --workpath=temp --paths=../shared ../cxquerymerger/cxquerymerger.py
cp ../cxquerymerger/src/cxquerymergerconfig.yaml ../.dist/cxquerymerger/ubuntu/config.yaml
cp ../LICENSE ../.dist/cxquerymerger/ubuntu/LICENSE
rm -f -r --interactive=never cxquerymerger.spec
rm -f -r --interactive=never temp
tar -czvf ../.dist/cxquerymerger-ubuntu64.tar.gz -C ../.dist/cxquerymerger/ubuntu .

# ---------------------------
# Create cxscanner executable
# ---------------------------
pyinstaller --clean --noconfirm --onefile --nowindow --distpath=../.dist/cxscanner/ubuntu --workpath=temp --paths=../shared ../cxscanner/cxscanner.py
cp ../cxscanner/src/cxscannerconfig.yaml ../.dist/cxscanner/ubuntu/config.yaml
cp ../LICENSE ../.dist/cxscanner/ubuntu/LICENSE
rm -f -r --interactive=never cxscanner.spec
rm -f -r --interactive=never temp
tar -czvf ../.dist/cxscanner-ubuntu64.tar.gz -C ../.dist/cxscanner/ubuntu .

popd