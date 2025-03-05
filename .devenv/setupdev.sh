#!/bin/bash
# --------------------------
# SETUP YOUR DEV ENVIRONMENT
# --------------------------
# This shall be the first thing to run on your development environment
# --------------------------

pushd $(dirname "$0")

# Install/upgrade python pre-commit hook handler
pip install commitlint --upgrade

# Install/upgrade python linters and code checkers
pip install ruff --upgrade

# Install/upgrade python semantic-release SemVer
pip install python-semantic-release --upgrade

# Install python compiler (to build python pseudo executables)
pip install pyinstaller --upgrade
pip install pyinstaller-versionfile --upgrade

# Create a requirements file at root
if [ ! -e ../requirements.txt ] ; then
    touch ../requirements.txt
fi

# Setup vscode
if [ ! -e ../.vscode/ ] ; then
    mkdir ../.vscode
fi
if [ ! -e ../.vscode/launch.json ] ; then
    cp .settings/.vscode-launch.json ../.vscode/launch.json
fi
if [ ! -e ../.vscode/settings.json ] ; then
    cp .settings/.vscode-settings.json ../.vscode/settings.json
fi

# Install git hooks
cp -f .settings/.commit-msg-hook ../.git/hooks/commit-msg
cp -f .settings/.pre-commit-hook ../.git/hooks/pre-commit

cp -f .settings/.checkcode.sh ../checkcode.sh
chmod +x ../checkcode.sh

popd
