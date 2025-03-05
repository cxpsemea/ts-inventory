:: ------------------------
:: SETUP SUBMODULE "SHARED"
:: ------------------------
:: This will add "./shared" submodule to your project
:: --------------------------
@echo off
pushd "%~dp0"

cd ..
git submodule add --name shared https://github.com/cxpsemea/ts-pythonshared shared

popd