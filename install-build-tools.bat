@echo off
rem Installs the minimum needed to run build.bat:
rem   Build Tools for Visual Studio 2022 (MSVC + Windows SDK, no IDE) via winget.
rem Administrator approval (UAC) is requested by the installer.
setlocal

where winget >nul 2>&1
if errorlevel 1 goto no_winget

winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--passive --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
if errorlevel 1 exit /b 1

echo.
echo Done. Open a new prompt and run: build.bat
exit /b 0

:no_winget
echo winget not found. Install "Build Tools for Visual Studio" manually:
echo   https://visualstudio.microsoft.com/downloads/  (Tools for Visual Studio)
echo and select the "Desktop development with C++" workload.
exit /b 1
