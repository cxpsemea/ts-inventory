@echo off
pushd "%~dp0"

:: -----------------------------
:: Create cxinventory executable
:: -----------------------------
create-version-file ..\cxinventory\src\cxinventorymanifestwindows.yaml --outfile cxinventorymanifestwindows.txt
pyinstaller --clean --noconfirm --onefile --nowindow --distpath=..\.dist\cxinventory\windows --workpath=temp --paths=..\shared --version-file=cxinventorymanifestwindows.txt --icon=..\shared\imaging\icon.ico ..\cxinventory\cxinventory.py
copy ..\cxinventory\src\cxinventoryconfig.yaml ..\.dist\cxinventory\windows\config.yaml
copy ..\LICENSE ..\.dist\cxinventory\windows\LICENSE
del cxinventorymanifestwindows.txt
del cxinventory.spec
rmdir /s /q temp
powershell Compress-Archive -Force -CompressionLevel Optimal -Path ..\.dist\cxinventory\windows\* ..\.dist\cxinventory-win64.zip

popd
