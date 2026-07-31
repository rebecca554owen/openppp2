$ErrorActionPreference = 'Stop'

$DevRoot = 'E:\Dev'
$Downloads = Join-Path $DevRoot 'downloads'
$JdkZip = Join-Path $Downloads 'jdk17.zip'
$CmdToolsZip = Join-Path $Downloads 'commandlinetools.zip'
$JdkRoot = Join-Path $DevRoot 'jdk-17'
$FlutterRoot = Join-Path $DevRoot 'flutter'
$AndroidSdkRoot = Join-Path $DevRoot 'Android\Sdk'
$Proxy = 'http://127.0.0.1:2081'
$ProxyHost = '127.0.0.1'
$ProxyPort = '2081'

$env:HTTP_PROXY = $Proxy
$env:HTTPS_PROXY = $Proxy
$env:ALL_PROXY = $Proxy

function Add-UserPathItem($PathItem) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ([string]::IsNullOrWhiteSpace($userPath)) {
        $userPath = ''
    }
    if ($userPath -notlike "*$PathItem*") {
        [Environment]::SetEnvironmentVariable('Path', "$userPath;$PathItem", 'User')
    }
}

function Invoke-Step($Name, [scriptblock]$Action) {
    Write-Host "\n==> $Name" -ForegroundColor Cyan
    & $Action
}

New-Item -ItemType Directory -Force -Path $DevRoot, $Downloads, $AndroidSdkRoot | Out-Null

Invoke-Step 'Install JDK 17' {
    if (-not (Test-Path (Join-Path $JdkRoot 'bin\java.exe'))) {
        & curl.exe --proxy $Proxy -L --fail --continue-at - --output $JdkZip 'https://aka.ms/download-jdk/microsoft-jdk-17-windows-x64.zip'
        $extractRoot = Join-Path $DevRoot 'jdk-extract'
        if (Test-Path $extractRoot) { Remove-Item -Recurse -Force $extractRoot }
        Expand-Archive -Force $JdkZip $extractRoot
        $extracted = Get-ChildItem $extractRoot -Directory | Select-Object -First 1
        if (-not $extracted) { throw 'JDK archive extraction failed.' }
        if (Test-Path $JdkRoot) { Remove-Item -Recurse -Force $JdkRoot }
        Move-Item $extracted.FullName $JdkRoot
        Remove-Item -Recurse -Force $extractRoot
    }
    & (Join-Path $JdkRoot 'bin\java.exe') -version
}

Invoke-Step 'Install Flutter stable' {
    if (-not (Test-Path (Join-Path $FlutterRoot 'bin\flutter.bat'))) {
        if (Test-Path $FlutterRoot) { Remove-Item -Recurse -Force $FlutterRoot }
        git -c http.proxy=$Proxy -c https.proxy=$Proxy clone --depth 1 https://github.com/flutter/flutter.git -b stable $FlutterRoot
    }
    $env:PUB_HOSTED_URL = 'https://pub.flutter-io.cn'
    $env:FLUTTER_STORAGE_BASE_URL = 'https://storage.flutter-io.cn'
    [Environment]::SetEnvironmentVariable('PUB_HOSTED_URL', $env:PUB_HOSTED_URL, 'User')
    [Environment]::SetEnvironmentVariable('FLUTTER_STORAGE_BASE_URL', $env:FLUTTER_STORAGE_BASE_URL, 'User')
    & (Join-Path $FlutterRoot 'bin\flutter.bat') --version
}

Invoke-Step 'Install Android command-line tools' {
    $sdkManager = Join-Path $AndroidSdkRoot 'cmdline-tools\latest\bin\sdkmanager.bat'
    if (-not (Test-Path $sdkManager)) {
        Invoke-WebRequest -Proxy $Proxy -Uri 'https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip' -OutFile $CmdToolsZip
        $extractRoot = Join-Path $Downloads 'cmdtools-extract'
        if (Test-Path $extractRoot) { Remove-Item -Recurse -Force $extractRoot }
        Expand-Archive -Force $CmdToolsZip $extractRoot
        $latestRoot = Join-Path $AndroidSdkRoot 'cmdline-tools\latest'
        if (Test-Path $latestRoot) { Remove-Item -Recurse -Force $latestRoot }
        New-Item -ItemType Directory -Force -Path $latestRoot | Out-Null
        Copy-Item -Recurse -Force (Join-Path $extractRoot 'cmdline-tools\*') $latestRoot
        Remove-Item -Recurse -Force $extractRoot
    }
    if (-not (Test-Path $sdkManager)) { throw 'sdkmanager was not installed correctly.' }
}

$env:JAVA_HOME = $JdkRoot
$env:ANDROID_HOME = $AndroidSdkRoot
$env:ANDROID_SDK_ROOT = $AndroidSdkRoot
$env:Path = "$(Join-Path $JdkRoot 'bin');$(Join-Path $FlutterRoot 'bin');$(Join-Path $AndroidSdkRoot 'platform-tools');$(Join-Path $AndroidSdkRoot 'cmdline-tools\latest\bin');$env:Path"

[Environment]::SetEnvironmentVariable('JAVA_HOME', $JdkRoot, 'User')
[Environment]::SetEnvironmentVariable('ANDROID_HOME', $AndroidSdkRoot, 'User')
[Environment]::SetEnvironmentVariable('ANDROID_SDK_ROOT', $AndroidSdkRoot, 'User')
Add-UserPathItem (Join-Path $JdkRoot 'bin')
Add-UserPathItem (Join-Path $FlutterRoot 'bin')
Add-UserPathItem (Join-Path $AndroidSdkRoot 'platform-tools')
Add-UserPathItem (Join-Path $AndroidSdkRoot 'cmdline-tools\latest\bin')

Invoke-Step 'Install Android SDK packages' {
    $sdkManager = Join-Path $AndroidSdkRoot 'cmdline-tools\latest\bin\sdkmanager.bat'
    $yes = ('y' + [Environment]::NewLine) * 100
    $yes | & $sdkManager --sdk_root=$AndroidSdkRoot --proxy=http --proxy_host=$ProxyHost --proxy_port=$ProxyPort --licenses
    $yes | & $sdkManager --sdk_root=$AndroidSdkRoot --proxy=http --proxy_host=$ProxyHost --proxy_port=$ProxyPort --install 'platform-tools' 'cmdline-tools;latest' 'platforms;android-35' 'build-tools;35.0.0' 'platforms;android-34' 'build-tools;34.0.0'
}

Invoke-Step 'Configure Flutter' {
    $flutter = Join-Path $FlutterRoot 'bin\flutter.bat'
    $env:PUB_HOSTED_URL = 'https://pub.flutter-io.cn'
    $env:FLUTTER_STORAGE_BASE_URL = 'https://storage.flutter-io.cn'
    & $flutter config --android-sdk $AndroidSdkRoot
    & $flutter doctor -v
}

Write-Host "\nDevelopment environment installed. Restart PowerShell/IDE if PATH is not refreshed." -ForegroundColor Green
