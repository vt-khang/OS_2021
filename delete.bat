@echo off
setlocal enableextensions enabledelayedexpansion

for %%F in ("*.dat") do (
	set filename=%%~nF
	set /a last=!filename:~-1!
	set /a modulo=!last! %% 2
	if !modulo!==0 del "%%F" /s /q
)
endlocal