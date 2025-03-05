#!/bin/bash

pushd $(dirname "$0")

# -----------------------
# Create linux executable
# -----------------------
# Expects param with the python main file name (filename.py), which should be at repository root
filename=$1
if [ -z "$filename" ]; then
	echo Please supply a root file name
	exit 9
fi

# Sets appname variable
appname="${filename%.*}"

# Ensure we have pyinstaller
pip install --upgrade pyinstaller

# Build executable
pyinstaller --clean --noconfirm --onefile --nowindow --distpath=../.dist/macos --workpath=temp --paths=../shared --icon=.resources/icon.icns ../$filename

# Cleanup
rm -f -r $appname.spec
rm -f -r temp

# Bundle tar.gz
if [ -e ../src/cxconfig.yaml ]; then
	cp ../src/cxconfig.yaml ../.dist/macos/config.yaml
fi
if [ -e ../LICENSE ]; then
	cp ../LICENSE ../.dist/macos/LICENSE
fi
tar -czvf ../.dist/$appname-macos.tar.gz -C ../.dist/macos .

popd