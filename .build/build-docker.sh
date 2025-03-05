#!/bin/bash

pushd $(dirname "$0")

# ---------------------------------
# Create docker container image tar
# ---------------------------------
# Expects param with the python main file name (filename.py), which should be at repository root
filename=$1
if [ -z "$filename" ]; then
	echo Please supply a root file name
	exit 9
fi

# Supports another parameter with tag (defaults to "latest")
filetag=$2
if [ -z "$filetag" ]; then
	filetag=latest
fi

# Sets appname variable
appname="${filename%.*}"

# Gets docker file name
dockername=dockerfile

# Checks if a docker file exists at root, or create one if missing
if [ ! -e ../$dockername ]; then
	cp .resources/alpine_docker_template.txt ../dockerfilexx
	cat .resources/docker_template.txt >> ../dockerfilexx
	dockername=dockerfilexx
fi

# Apply variable changes in dockerfile
sed -i -e "s/{{filename}}/$filename/g" ../$dockername
sed -i -e "s/{{appname}}/$appname/g" ../$dockername

# Run docker file 
cd ..
mkdir -p .dist
docker build -t $appname:$filetag -f $dockername -o type=tar,dest=.dist/$appname-docker.tar .

# Remove docker file if x
if [ -e dockerfilexx ]; then
	rm -f -r --interactive=never dockerfilexx
fi

popd