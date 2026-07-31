$env:JAVA_HOME='E:\Dev\jdk-17'
$env:ANDROID_HOME='E:\Dev\Android\Sdk'
$env:PATH='E:\Dev\flutter-new\bin;E:\Dev\jdk-17\bin;' + $env:PATH
Set-Location -LiteralPath 'E:\Desktop\openppp2-next\openppp2_mobile\android'
.\gradlew.bat :app:assembleDebug "-Ptarget-platform=android-arm64" "-Ptarget=lib/main.dart" "-Pbase-application-name=android.app.Application" --no-watch-fs --stacktrace
