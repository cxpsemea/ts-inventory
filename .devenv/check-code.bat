@echo off

:: --------------------------
:: LINT THE CODE
:: --------------------------
if %1.==lint. (
	if %2.==fix. (
		echo ####################################################################
		echo ## Check and fix code format - lint
		echo ####################################################################
		pushd "%~dp0"
		cd ..
		ruff check . --fix --config .devenv/.settings/.ruff.toml
		popd
	) else (
		echo ####################################################################
		echo ## Check code format - lint
		echo ####################################################################
		pushd "%~dp0"
		cd ..
		ruff check . --config .devenv/.settings/.ruff.toml
		popd
	)
) else (
	echo No valid command passed
	echo Use "lint", "lint fix"
)