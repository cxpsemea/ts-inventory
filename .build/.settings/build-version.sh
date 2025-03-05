#!/bin/bash

pushd $(dirname "$0")

# Expects param with the version 
version=$1
if [ -z "$version" ]; then
	echo Please supply a version number
	exit 9
fi

# Check if version file exists
if [ -e ../../shared/common/cxversion.py ] ; then
    echo "cxversion: str = '$version'" > ../../shared/common/cxversion.py
fi

popd