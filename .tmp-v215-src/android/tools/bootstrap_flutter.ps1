$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$BackupRoot = Join-Path $ProjectRoot '.bootstrap-backup'

function Assert-Command($Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name was not found in PATH. Please install Flutter first and restart PowerShell."
    }
}

Assert-Command flutter

if (Test-Path $BackupRoot) {
    Remove-Item -Recurse -Force $BackupRoot
}
New-Item -ItemType Directory -Force -Path $BackupRoot | Out-Null

$ItemsToBackup = @(
    'lib',
    'android/app/src/main/kotlin',
    'android/app/src/main/jniLibs',
    'android/app/src/main/res',
    'android/app/src/main/AndroidManifest.xml',
    'android/app/build.gradle',
    'android/build.gradle',
    'android/settings.gradle',
    'android/gradle.properties',
    'pubspec.yaml',
    'analysis_options.yaml',
    'README.md',
    '.gitignore'
)

foreach ($Item in $ItemsToBackup) {
    $Source = Join-Path $ProjectRoot $Item
    if (Test-Path $Source) {
        $Target = Join-Path $BackupRoot $Item
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Target) | Out-Null
        Copy-Item -Recurse -Force $Source $Target
    }
}

Push-Location $ProjectRoot
try {
    flutter create --overwrite --project-name openppp2_mobile --org supersocksr.ppp --platforms android .
} finally {
    Pop-Location
}

foreach ($Item in $ItemsToBackup) {
    $Source = Join-Path $BackupRoot $Item
    if (Test-Path $Source) {
        $Target = Join-Path $ProjectRoot $Item
        if (Test-Path $Target) {
            Remove-Item -Recurse -Force $Target
        }
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Target) | Out-Null
        Copy-Item -Recurse -Force $Source $Target
    }
}

Push-Location $ProjectRoot
try {
    flutter pub get
    flutter doctor
} finally {
    Pop-Location
}

Write-Host 'Bootstrap finished. You can now run: flutter run' -ForegroundColor Green
