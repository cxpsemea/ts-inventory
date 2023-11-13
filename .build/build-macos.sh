#!/bin/bash

pushd $(dirname "$0")

# -------------------------------
# GITHUB runner don't support ARM
# GitHub workflow sends "GITHUB-RUNNER"
# parameter if a macos runner is used
# -------------------------------

# -------------------------------------
# Put icon icns file in the same folder
# -------------------------------------
cp ../shared/imaging/icon.icns icon.icns

# -----------------------------
# Create cxinventory executable
# -----------------------------
pyinstaller --clean --noconfirm --onefile --nowindow --distpath=../.dist/cxinventory/macos ---workpath=temp --paths=../shared --icon=icon.icns ../cxinventory/cxinventory.py
cp ../cxinventory/src/cxinventoryconfig.yaml ../.dist/cxinventory/macos/config.yaml
cp ../LICENSE ../.dist/cxinventory/macos/LICENSE
rm -f -r --interactive=never cxinventory.spec
rm -f -r --interactive=never temp
tar -czvf ../.dist/cxinventory-macos.tar.gz -C ../.dist/cxinventory/macos .

# --------------------------------
# Create cxquerymerger executable
# --------------------------------
pyinstaller --clean --noconfirm --onefile --nowindow --distpath=../.dist/cxquerymerger/macos --workpath=temp --paths=../shared --icon=icon.icns ../cxquerymerger/cxquerymerger.py
cp ../cxquerymerger/src/cxquerymergerconfig.yaml ../.dist/cxquerymerger/macos/config.yaml
cp ../LICENSE ../.dist/cxquerymerger/macos/LICENSE
rm -f -r --interactive=never cxquerymerger.spec
rm -f -r --interactive=never temp
tar -czvf ../.dist/cxquerymerger-macos.tar.gz -C ../.dist/cxquerymerger/macos .

# ---------------------------
# Create cxscanner executable
# ---------------------------
pyinstaller --clean --noconfirm --onefile --nowindow --distpath=../.dist/cxscanner/macos --workpath=temp --paths=../shared --icon=icon.icns ../cxscanner/cxscanner.py
cp ../cxscanner/src/cxscannerconfig.yaml ../.dist/cxscanner/macos/config.yaml
cp ../LICENSE ../.dist/cxscanner/macos/LICENSE
rm -f -r --interactive=never cxscanner.spec
rm -f -r --interactive=never temp
tar -czvf ../.dist/cxscanner-macos.tar.gz -C ../.dist/cxscanner/macos .

popd