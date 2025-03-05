:: --------------------------
:: SETUP YOUR DEV ENVIRONMENT
:: --------------------------
:: This shall be the first thing to run on your development environment
:: --------------------------
@echo off
pushd "%~dp0"

:: Install/upgrade python pre-commit hook handler
pip install commitlint --upgrade

:: Install/upgrade python linters and code checkers
pip install ruff --upgrade

:: Install/upgrade python semantic-release SemVer
pip install python-semantic-release --upgrade

:: Install python compiler (to build python pseudo executables)
pip install pyinstaller --upgrade
pip install pyinstaller-versionfile --upgrade

:: Create a requirements file at root
if not exist ..\requirements.txt (
    copy nul ..\requirements.txt
)

:: Setup vscode
if not exist ..\.vscode\ (
    mkdir ..\.vscode
)
if not exist ..\.vscode\launch.json (
    copy .settings\.vscode-launch.json ..\.vscode\launch.json
)
if not exist ..\.vscode\settings.json (
    copy .settings\.vscode-settings.json ..\.vscode\settings.json
)

:: Install git hooks
copy /Y .settings\.commit-msg-hook ..\.git\hooks\commit-msg
copy /Y .settings\.pre-commit-hook ..\.git\hooks\pre-commit

copy /Y .settings\.checkcode.bat ..\checkcode.bat

popd
