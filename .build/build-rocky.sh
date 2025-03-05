#!/bin/bash

pushd $(dirname "$0")

# -----------------------------
# Create rocky linux executable
# -----------------------------
# Expects param with the python main file name (filename.py), which should be at repository root
filename=$1
if [ -z "$filename" ]; then
	echo Please supply a root file name
	exit 9
fi

# Sets appname variable
appname="${filename%.*}"

# Copy template dockerfile to root
cp .resources/rocky_docker_template.txt ../dockerfilex

# Apply variable changes in dockerfile
sed -i -e "s/{{filename}}/$filename/g" ../dockerfilex
sed -i -e "s/{{appname}}/$appname/g" ../dockerfilex

# Run docker file 
cd ..
docker build -t $appname:rocky_xxx -f dockerfilex .

# Copy artifact to .dist
docker create --name dummyxx $appname:rocky_xxx
docker cp dummyxx:/opt/app/.dist/ .
docker rm -f dummyxx

# Remove docker image
docker rmi $appname:rocky_xxx

# Remove docker file
rm -f -r --interactive=never dockerfilex

popd