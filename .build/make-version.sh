#!/bin/bash
pushd $(dirname "$0")
echo "version = { 'version': '$1' }" > ../shared/version.py
popd