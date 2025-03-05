@echo off

pushd "%~dp0"

:: Expects param with the version 
if [%1] == [] (
    echo Please supply a version number
    exit /b 9
)   

:: Check if version file exists
if exist ..\..\shared\common\cxversion.py (
    echo cxversion: str = '%1' > ..\..\shared\common\cxversion.py
)

popd