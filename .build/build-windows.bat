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
powershell Compress-Archive -Force -CompressionLevel Optimal -Path ..\.dist\cxinventory\windows\*.* ..\.dist\cxinventory-win64.zip

:: -------------------------------
:: Create cxquerymerger executable
:: -------------------------------
create-version-file ..\cxquerymerger\src\cxquerymergermanifestwindows.yaml --outfile cxquerymergermanifestwindows.txt
pyinstaller --clean --noconfirm --onefile --nowindow --distpath=..\.dist\cxquerymerger\windows --workpath=temp --paths=..\shared --version-file=cxquerymergermanifestwindows.txt --icon=..\shared\imaging\icon.ico ..\cxquerymerger\cxquerymerger.py
copy ..\cxquerymerger\src\cxquerymergerconfig.yaml ..\.dist\cxquerymerger\windows\config.yaml
copy ..\LICENSE ..\.dist\cxquerymerger\windows\LICENSE
del cxquerymergermanifestwindows.txt
del cxquerymerger.spec
rmdir /s /q temp
powershell Compress-Archive -Force -CompressionLevel Optimal -Path ..\.dist\cxquerymerger\windows\*.* ..\.dist\cxquerymerger-win64.zip

:: ---------------------------
:: Create cxscanner executable
:: ---------------------------
create-version-file ..\cxscanner\src\cxscannermanifestwindows.yaml --outfile cxscannermanifestwindows.txt
pyinstaller --clean --noconfirm --onefile --nowindow --distpath=..\.dist\cxscanner\windows --workpath=temp --paths=..\shared --version-file=cxscannermanifestwindows.txt --icon=..\shared\imaging\icon.ico ..\cxscanner\cxscanner.py
copy ..\cxscanner\src\cxscannerconfig.yaml ..\.dist\cxscanner\windows\config.yaml
copy ..\LICENSE ..\.dist\cxscanner\windows\LICENSE
del cxscannermanifestwindows.txt
del cxscanner.spec
rmdir /s /q temp
powershell Compress-Archive -Force -CompressionLevel Optimal -Path ..\.dist\cxscanner\windows\*.* ..\.dist\cxscanner-win64.zip


popd
