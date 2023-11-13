#!/bin/bash
# pushd $(dirname "$0")
cd .build
echo "version = { 'version': '$1' }" > ../shared/version.py
cd ..
# popd
