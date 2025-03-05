@echo off
pushd "%~dp0"

:: -------------------------
:: Create windows executable
:: -------------------------

:: Expects param with the python main file name (filename.py), which should be at repository root
set filename=%1
if "%filename%"=="" (
	echo Please supply a root file name
	exit /b 9
)

:: Supports another parameter with version (defaults to 0.0.0.0)
set fileversion=%2
if "%fileversion%"=="" set fileversion=0.0.0.0
set manifestversion=%fileversion:-rc.=.%
set manifestversion=%fileversion:v=%
set count=0
for %%a in (%manifestversion:.= %) do set /a count+=1
if %count% LSS 4 set manifestversion=%manifestversion%.0
set manifestversion=(%manifestversion:.=,%)

:: Sets appname and executable name variables
for %%f in ("%filename%") do set appname=%%~nf
set exename=%appname%.exe

:: Ensure we have pyinstaller
pip install --upgrade pyinstaller

:: Compose the window version file from template
powershell -Command "(Get-Content .resources\version_file_template.txt) | Foreach-Object { $_ -replace '{{Version}}', '%fileversion%' -replace '{{FileVersion}}', '%manifestversion%' -replace '{{ProdVersion}}', '%manifestversion%' -replace '{{FileDescription}}', '%appname%' -replace '{{InternalName}}', '%appname%' -replace '{{OriginalFilename}}', '%exename%' } | Set-Content manifest.txt"

:: Build executable
pyinstaller --clean --noconfirm --onefile --nowindow --distpath=..\.dist\windows --workpath=temp --paths=..\shared --version-file=manifest.txt --icon=.resources\icon.ico ..\%filename%

:: Cleanup
del /f /q manifest.txt
del /f /q %appname%.spec
del /f /s /q temp 1>nul
rmdir /s /q temp

:: Bundle zip
if exist ..\src\cxconfig.yaml copy ..\src\cxconfig.yaml ..\.dist\windows\config.yaml
if exist ..\LICENSE copy ..\LICENSE ..\.dist\windows\LICENSE
powershell Compress-Archive -Force -CompressionLevel Optimal -Path ..\.dist\windows\* ..\.dist\%appname%-win64.zip

popd