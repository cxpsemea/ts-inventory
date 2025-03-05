#!/bin/bash

pushd $(dirname "$0")

# ------------------------------
# Create ununtu linux executable
# ------------------------------
# Expects param with the python main file name (filename.py), which should be at repository root
filename=$1
if [ -z "$filename" ]; then
	echo Please supply a root file name
	exit 9
fi

# Expects param with the binary executable name 
appname="${filename%.*}"

# Ensure we have pyinstaller
pip install --upgrade pyinstaller

# Build executable
pyinstaller --clean --noconfirm --onefile --nowindow --distpath=../.dist/ubuntu --workpath=temp --paths=../shared ../$filename

# Cleanup
rm -f -r --interactive=never $appname.spec
rm -f -r --interactive=never temp

# Bundle tar.gz
if [ -e ../src/cxconfig.yaml ]; then
	cp ../src/cxconfig.yaml ../.dist/ubuntu/config.yaml
fi
if [ -e ../LICENSE ]; then
	cp ../LICENSE ../.dist/ubuntu/LICENSE
fi
tar -czvf ../.dist/$appname-ubuntu64.tar.gz -C ../.dist/ubuntu .

popd