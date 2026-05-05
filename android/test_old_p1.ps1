$adb = 'E:\Dev\Android\Sdk\platform-tools\adb.exe'
$device = 'adb-1b0e65b7-wdkDOv (2)._adb-tls-connect._tcp'
& $adb -s $device shell "ping -c 4 -W 3 1.1.1.1"
