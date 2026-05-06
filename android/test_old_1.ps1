$adb = 'E:\Dev\Android\Sdk\platform-tools\adb.exe'
$device = 'adb-1b0e65b7-wdkDOv (2)._adb-tls-connect._tcp'
& $adb -s $device shell "curl -4 -m 8 -v http://1.1.1.1/"
