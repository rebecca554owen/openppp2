$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "============================================================"
Write-Host " openppp2 Windows x64 Release Build Script"
Write-Host "============================================================"

$projDir = "E:\Desktop\openppp2-next\openppp2"
$vcpkgRoot = "C:\vcpkg"
$triplet = "x64-windows-static"
$config = "Release"
$platform = "x64"

# Manually set MSVC environment (avoiding vcvarsall.bat which emits ANSI escape codes)
Write-Host "`n[1/5] Setting up MSVC environment manually..."

$msvcBase = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
$msvcVer = "14.44.35207"
$msvcTools = "$msvcBase\VC\Tools\MSVC\$msvcVer"
$winSdkBase = "C:\Program Files (x86)\Windows Kits\10"
$winSdkVer = "10.0.26100.0"
$winSdkLibVer = "10.0.26100.0"
$winSdkIncVer = "10.0.26100.0"

$env:PATH = "$msvcBase\VC\Tools\MSVC\$msvcVer\bin\Hostx64\x64;" +
    "$winSdkBase\bin\$winSdkVer\x64;" +
    "$msvcBase\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;" +
    "$msvcBase\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer;" +
    "$msvcBase\MSBuild\Current\Bin\amd64;" +
    "$msvcBase\Common7\IDE\;" +
    "$msvcBase\Common7\Tools\;" +
    "$env:SystemRoot\system32;$env:SystemRoot;$env:SystemRoot\System32\Wbem;$env:SystemRoot\System32\WindowsPowerShell\v1.0"

$env:INCLUDE = "$msvcTools\ATLMFC\include;$msvcTools\include;" +
    "$winSdkBase\include\$winSdkIncVer\ucrt;" +
    "$winSdkBase\include\$winSdkIncVer\shared;" +
    "$winSdkBase\include\$winSdkIncVer\um;" +
    "$winSdkBase\include\$winSdkIncVer\winrt;" +
    "$winSdkBase\include\$winSdkIncVer\cppwinrt"

$env:LIB = "$msvcTools\ATLMFC\lib\x64;$msvcTools\lib\x64;" +
    "$winSdkBase\lib\$winSdkLibVer\ucrt\x64;" +
    "$winSdkBase\lib\$winSdkLibVer\um\x64"

$env:LIBPATH = "$msvcTools\ATLMFC\lib\x64;$msvcTools\lib\x64;" +
    "$env:SystemRoot\SysWOW64;$env:SystemRoot\system32;" +
    "$winSdkBase\lib\$winSdkLibVer\ucrt\x64;" +
    "$winSdkBase\lib\$winSdkLibVer\um\x64;" +
    "$msvcTools\lib\x64;$msvcTools\ATLMFC\lib\x64"

$env:Platform = "X64"
$env:VSCMD_ARG_HOST_ARCH = "x64"
$env:VSCMD_ARG_TGT_ARCH = "x64"

Write-Host "MSVC tools: $msvcTools"
$clPath = "$msvcTools\bin\Hostx64\x64\cl.exe"
if (-not (Test-Path $clPath)) {
    Write-Error "cl.exe not found at $clPath"
    exit 1
}
Write-Host "cl.exe found: $clPath"

# Step 2: Install vcpkg
Write-Host "`n[2/5] Setting up vcpkg..."
if (-not (Test-Path "$vcpkgRoot\vcpkg.exe")) {
    Write-Host "Cloning vcpkg..."
    if (Test-Path $vcpkgRoot) { Remove-Item -Recurse -Force $vcpkgRoot }
    git clone https://github.com/microsoft/vcpkg.git $vcpkgRoot
    Write-Host "Bootstrapping vcpkg..."
    & "$vcpkgRoot\bootstrap-vcpkg.bat" -disableMetrics
    if ($LASTEXITCODE -ne 0) {
        Write-Error "vcpkg bootstrap failed"
        exit 1
    }
} else {
    Write-Host "vcpkg already installed at $vcpkgRoot"
    # Update to latest
    Push-Location $vcpkgRoot
    git pull
    & "$vcpkgRoot\bootstrap-vcpkg.bat" -disableMetrics
    Pop-Location
}

# Step 3: Install dependencies
Write-Host "`n[3/5] Installing vcpkg dependencies (first run takes 30-60 min)..."
$packages = @(
    "boost-system", "boost-asio", "boost-beast", "boost-coroutine",
    "boost-thread", "boost-context", "boost-regex", "boost-filesystem",
    "boost-date-time", "boost-lockfree", "boost-lexical-cast", "boost-uuid",
    "boost-interprocess", "boost-stacktrace", "openssl", "jemalloc"
)

foreach ($pkg in $packages) {
    Write-Host "  Installing $pkg ($triplet)..."
    & "$vcpkgRoot\vcpkg.exe" install "$pkg`:$triplet"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "vcpkg install $pkg failed"
        exit 1
    }
}
Write-Host "All dependencies installed."

# Step 4: Integrate and build
Write-Host "`n[4/5] Building ppp.exe ($config|$platform)..."
& "$vcpkgRoot\vcpkg.exe" integrate install

$msbuild = "$msvcBase\MSBuild\Current\Bin\amd64\MSBuild.exe"
Write-Host "MSBuild: $msbuild"
& $msbuild "$projDir\ppp.vcxproj" /m /restore `
    "/p:Configuration=$config" `
    "/p:Platform=$platform" `
    /p:VcpkgEnableManifest=false `
    /p:VcpkgEnabled=true `
    /p:VcpkgUseStatic=true
if ($LASTEXITCODE -ne 0) {
    Write-Error "MSBuild failed (exit $LASTEXITCODE)"
    exit 1
}
Write-Host "Build succeeded."

# Step 5: Copy output
Write-Host "`n[5/5] Copying ppp.exe to target..."
$output = "$projDir\x64\Release\ppp.exe"
if (-not (Test-Path $output)) {
    Write-Error "ppp.exe not found at $output"
    exit 1
}
$target = "E:\Desktop\test-openppp2\ppp.exe"
Copy-Item -Force $output $target
Write-Host "`n============================================================"
Write-Host " DONE: ppp.exe copied to $target"
Write-Host "============================================================"
Get-Item $target
