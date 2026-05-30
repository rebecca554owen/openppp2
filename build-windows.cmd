@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo  openppp2 Windows x64 Release Build Script
echo ============================================================

set "PROJ_DIR=%~dp0"
set "PROJ_DIR=%PROJ_DIR:~0,-1%"
set "VCPKG_ROOT=C:\vcpkg"
set "TRIPLET=x64-windows-static"
set "CONFIG=Release"
set "PLATFORM=x64"

REM Step 1: Setup MSVC environment
echo.
echo [1/5] Setting up MSVC environment...
set "VCVARSALL=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "%VCVARSALL%" (
    echo ERROR: vcvarsall.bat not found at "%VCVARSALL%"
    exit /b 1
)
call "%VCVARSALL%" x64
if errorlevel 1 (
    echo ERROR: vcvarsall.bat failed
    exit /b 1
)
echo MSVC environment OK.

REM Step 2: Install vcpkg
echo.
echo [2/5] Setting up vcpkg...
if not exist "%VCPKG_ROOT%\vcpkg.exe" (
    echo Cloning vcpkg...
    if exist "%VCPKG_ROOT%" rmdir /s /q "%VCPKG_ROOT%"
    git clone https://github.com/microsoft/vcpkg.git "%VCPKG_ROOT%"
    if errorlevel 1 (
        echo ERROR: git clone vcpkg failed
        exit /b 1
    )
    call "%VCPKG_ROOT%\bootstrap-vcpkg.bat"
    if errorlevel 1 (
        echo ERROR: vcpkg bootstrap failed
        exit /b 1
    )
) else (
    echo vcpkg already installed.
)

REM Step 3: Install dependencies
echo.
echo [3/5] Installing vcpkg dependencies (this may take a while on first run)...
"%VCPKG_ROOT%\vcpkg.exe" install --triplet %TRIPLET% ^
    boost-system ^
    boost-asio ^
    boost-beast ^
    boost-coroutine ^
    boost-thread ^
    boost-context ^
    boost-regex ^
    boost-filesystem ^
    boost-date-time ^
    boost-lockfree ^
    boost-lexical-cast ^
    boost-uuid ^
    boost-interprocess ^
    boost-stacktrace ^
    openssl ^
    jemalloc
if errorlevel 1 (
    echo ERROR: vcpkg install failed
    exit /b 1
)
echo Dependencies installed.

REM Step 4: Integrate vcpkg and build
echo.
echo [4/5] Building ppp.exe (%CONFIG%^|%PLATFORM%)...
"%VCPKG_ROOT%\vcpkg.exe" integrate install

msbuild "%PROJ_DIR%\ppp.vcxproj" /m /restore ^
    /p:Configuration=%CONFIG% ^
    /p:Platform=%PLATFORM% ^
    /p:VcpkgEnableManifest=false ^
    /p:VcpkgEnabled=true ^
    /p:VcpkgUseStatic=true
if errorlevel 1 (
    echo ERROR: MSBuild failed
    exit /b 1
)
echo Build succeeded.

REM Step 5: Copy output
echo.
echo [5/5] Copying ppp.exe to target...
set "OUTPUT=%PROJ_DIR%\x64\Release\ppp.exe"
if not exist "%OUTPUT%" (
    echo ERROR: ppp.exe not found at "%OUTPUT%"
    exit /b 1
)

set "TARGET=E:\Desktop\test-openppp2\ppp.exe"
copy /y "%OUTPUT%" "%TARGET%"
if errorlevel 1 (
    echo ERROR: copy failed
    exit /b 1
)
echo.
echo ============================================================
echo  DONE: ppp.exe copied to %TARGET%
echo ============================================================
dir "%TARGET%"
