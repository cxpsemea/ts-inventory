@echo off
pushd "%~dp0"
:: Apply version to python about file
echo version = { 'version': '%1' } > ..\shared\version.py
:: Apply version to manifests
powershell -NoProfile -Command "$x = Get-Content -Encoding UTF8 '..\cxinventory\src\cxinventorymanifestwindows.yaml'; $x[0] = 'Version: %1'; $x | Out-File -Encoding UTF8 '..\cxinventory\src\cxinventorymanifestwindows.yaml'"
popd
