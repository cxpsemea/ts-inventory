#!/bin/bash

# --------------------------
# LINT THE CODE
# --------------------------
if [ "$1" = "lint" ]; then
    if [ "$2" = "fix" ]; then
        echo "####################################################################"
        echo "## Check and fix code format - lint"
        echo "####################################################################"
        pushd $(dirname "$0") > /dev/null
        cd ..
        ruff check . --fix --config .devenv/.settings/.ruff.toml
        popd > /dev/null
    else
        echo "####################################################################"
        echo "## Check code format - lint"
        echo "####################################################################"
        pushd $(dirname "$0") > /dev/null
        cd ..
        ruff check . --config .devenv/.settings/.ruff.toml
        popd > /dev/null
    fi
else
    echo "No valid command passed"
    echo 'Use "lint", "lint fix"'
fi