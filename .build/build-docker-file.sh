#!/bin/bash

pushd $(dirname "$0")

# -------------------------------------
# Prepares a docker file for publishing
# -------------------------------------
# Expects param with the python main file name (filename.py), which should be at repository root
filename=$1
if [ -z "$filename" ]; then
	echo Please supply a root file name
	exit 9
fi

# Sets appname variable
appname="${filename%.*}"

if [ -e ../dockerfile ]; then
    cp -f ../dockerfile ../dockerfilexx
else
	cp .resources/alpine_docker_template.txt ../dockerfilexx
	cat .resources/docker_template.txt >> ../dockerfilexx
fi

# Apply variable changes in dockerfile
sed -i -e "s/{{filename}}/$filename/g" ../dockerfilexx
sed -i -e "s/{{appname}}/$appname/g" ../dockerfilexx

popd