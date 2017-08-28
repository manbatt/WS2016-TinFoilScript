#For Server 2016 and Windows 10 Enterprise LTSB and LTSB N ONLY - will break some desktop services - activate spooler service, if you need printing functionality
#kill nasty services. Why does they even exist?
cls
Write-Host "Disabling Windows 10 services"
Start-Sleep 3;
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ajrouter" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdpsvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdpusersvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushsvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wpnservice" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wpnuserservice" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\userdataservice" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Xblauthmanager" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xblgamesave" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xboxnetapisvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagtrack" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\moshost" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\aphostservice" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pcasvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sensorservice" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sensrsvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sessenv" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\unistore" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wbiosrvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wdi" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wersvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v Start /d 4 /t "REG_DWORD" /f
set-service DPS -startuptype Disabled
set-service WdiServiceHost -startuptype Disabled
set-service WdiSystemHost -startuptype Disabled
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcncsvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\upnphost" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wisvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\icssvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppXSvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\upnphost" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Themes" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ScDeviceEnum" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCPolicySvc" /v Start /d 4 /t "REG_DWORD" /f

#Office promt
cls
write-host 'Do you use Microsoft Office and printing?'
write-host '1 = no'
write-host '2 = yes, i do use / will use Microsoft Office and printing'

$selected_menu_item = Read-Host 'Select menu item'

Switch($selected_menu_item){

1{reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sppsvc" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClipSVC" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler" /v Start /d 4 /t "REG_DWORD" /f
Write-Host "Disabling sppsvc, ClipSVC and Spooler"
Start-Sleep 2}

2{reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sppsvc" /v Start /d 1 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClipSVC" /v Start /d 1 /t "REG_DWORD" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler" /v Start /d 1 /t "REG_DWORD" /f
Write-Host "Enabling sppsvc, ClipSVC and Spooler"
Start-Sleep 2}

default {Write-Host 'Incorrect input' -ForegroundColor Red}

}


#SMB v1 promt
cls
write-host 'Do you want SMB v1 disabled? Note that serving files to older linux and OS X based OSes can be troubling'
write-host '1 = No, I serve files to older linux and OS X clients'
write-host '2 = Yes, I want SMB v1 disabled (more security against ransomware)'
write-host 'Information on disabling SMB v1 and enabling SMB v2 on linux: https://www.cyberciti.biz/faq/how-to-configure-samba-to-use-smbv2-and-disable-smbv1-on-linux-or-unix/'

$selected_menu_item = Read-Host 'Select menu item'

Switch($selected_menu_item){

1{cls
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 1 -Force
Write-Host "Enabing SMB v1"
Start-Sleep 2}

2{cls
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force
Write-Host "Disabling SMB v1"
Start-Sleep 2}

default {Write-Host 'Incorrect input' -ForegroundColor Red}

}


#Disable Teredo
cls
Write-Host "Disabling Teredo"
Start-Sleep 3
netsh interface teredo set state disabled


#Windows Defender services - deactivate
cls
Write-Host "Disabling Windows Defender";
Start-Sleep 3;
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d 4 /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d 4 /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d 4 /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d 4 /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d 4 /f  
regsvr32 /s /u "%ProgramFiles%\Windows Defender\shellext.dll"
taskkill /f /im MSASCuiL.exe
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v Start /d 4 /t "REG_DWORD" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /d 1 /t "REG_DWORD" /f









#Privacy
cls
Write-Host "Disabling Windows 10 analytics and telemetry"
Start-Sleep 3;
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /d 0 /t "REG_DWORD" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /d 0 /t "REG_DWORD" /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Cloud Content" /v DisableWindowsConsumerFeatures /d 1 /t "REG_DWORD" /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v NoTileApplicationNotification /d 1 /t "REG_DWORD" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /d 0 /t "REG_DWORD" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /d 0 /t "REG_DWORD" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenOverlayEnabled /d 0 /t "REG_DWORD" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenEnabled /d 0 /t "REG_DWORD" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /d 0 /t "REG_DWORD" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /d 0 /t "REG_DWORD" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreinstalledAppsEnabled /d 0 /t "REG_DWORD" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContentEnabled /d 0 /t "REG_DWORD" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /d 0 /t "REG_DWORD" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /d 0 /t "REG_DWORD" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v FeatureManagementEnabled /d 0 /t "REG_DWORD" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /d 0 /t "REG_DWORD" /f
reg load "HKLM\temp_default_profile" "C:\Users\Default\ntuser.dat"
reg add "HKLM\temp_default_profile\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /d 1 /t "REG_DWORD" /f
reg add "HKLM\temp_default_profile\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v NoTileApplicationNotification /d 1 /t "REG_DWORD" /f
reg add "HKLM\temp_default_profile\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /d 0 /t "REG_DWORD" /f
reg add "HKLM\temp_default_profile\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /d 0 /t "REG_DWORD" /f
reg add "HKLM\temp_default_profile\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenOverlayEnabled /d 0 /t "REG_DWORD" /f
reg add "HKLM\temp_default_profile\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenEnabled /d 0 /t "REG_DWORD" /f
reg add "HKLM\temp_default_profile\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /d 0 /t "REG_DWORD" /f
reg add "HKLM\temp_default_profile\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /d 0 /t "REG_DWORD" /f
reg add "HKLM\temp_default_profile\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreinstalledAppsEnabled /d 0 /t "REG_DWORD" /f
reg add "HKLM\temp_default_profile\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContentEnabled /d 0 /t "REG_DWORD" /f
reg add "HKLM\temp_default_profile\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /d 0 /t "REG_DWORD" /f
reg add "HKLM\temp_default_profile\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /d 0 /t "REG_DWORD" /f
reg add "HKLM\temp_default_profile\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v FeatureManagementEnabled /d 0 /t "REG_DWORD" /f
reg add "HKLM\temp_default_profile\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /d 0 /t "REG_DWORD" /f
reg unload "HKLM\temp_default_profile"

#Disable telemetry 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f 
reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f 
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushsvc" /v "Start" /t REG_DWORD /d 4 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d 4 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d 4 /f 


#Disable Windows Customer Experience Improvement Program 
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d "0.0.0.0" /f 


#Disable Application Telemetry 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f 


#Disable Inventory Collector 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f 


#Disable Steps Recorder 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f 


#Disable Advertising ID 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f 


#Disable keylogger 
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f 
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f 
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f 


#Disable browser access to local language 
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f 


#Disable SmartScreen 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f 
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f 


#Disable Cortana and web search 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d 3 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d 0 /f 


#Disable Wi-Fi Sense 
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d 0 /f 


#Disable biometrics 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d 4 /f 


#Disable location access and sensors 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d 1 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /v "Start" /t REG_DWORD /d 4 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d 0 /f 


#Disable sync 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d 2 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t REG_DWORD /d 2 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t REG_DWORD /d 2 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t REG_DWORD /d 2 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t REG_DWORD /d 2 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t REG_DWORD /d 2 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t REG_DWORD /d 2 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t REG_DWORD /d 2 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d 2 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t REG_DWORD /d 1 /f 


#Disable Delivery Optimization 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d 0 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d 4 /f 


#Disable Program Compatibility Assistant 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d 1 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d 4 /f 



#Disable Windows Error Reporting 
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f 


#Disable Windows Tips 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f 


#Disable Windows Consumer Features (App Suggestions on Start) 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f 



#Disable File History 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d 1 /f 


#Disable Active Help 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d 1 /f 


#Disable loggers 
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f 


#Disable Windows Feedback 
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f 


#Disable Microsoft Help feedback 
reg add "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d 1 /f 


#Disable feedback on write 
reg add "HKLM\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f 


#Disable lock screen camera 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f 


#Disable password reveal button 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d 1 /f 


#Disable Windows Insider Program 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d 0 /f 


#Disable DRM features 
reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f 


#Disable Office 2016 telemetry 
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" /v "Enablelogging" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" /v "EnableUpload" /t REG_DWORD /d 0 /f 


#Disable Game DVR 
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f 


#Disable Live Tiles 
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d 1 /f 


#Disable AutoPlay and AutoRun 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f 


#Disable Remote Assistance 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d 0 /f 


#Disable administrative shares 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d 0 /f 


#Do not send Windows Media Player statistics 
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f 

#Set default PhotoViewer
cls
Write-Host "Setting Photo Viewer as default photo app"
Start-Sleep 3; 
reg add "HKCU\SOFTWARE\Classes\.ico" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f 
reg add "HKCU\SOFTWARE\Classes\.tiff" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f 
reg add "HKCU\SOFTWARE\Classes\.bmp" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f 
reg add "HKCU\SOFTWARE\Classes\.png" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f 
reg add "HKCU\SOFTWARE\Classes\.gif" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f 
reg add "HKCU\SOFTWARE\Classes\.jpeg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f 
reg add "HKCU\SOFTWARE\Classes\.jpg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f 

cls
Write-Host "Miscellaneous - show hidden files etc."
Start-Sleep 3;

#Turn off "You have new apps that can open this type of file" alert 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoNewAppAlert" /t REG_DWORD /d 1 /f 


#Turn off "Look For An App In The Store" option 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d 1 /f 


#Do not show recently used files in Quick Access 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 0 /f 


#Do not show frequently used folders in Quick Access 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d 0 /f 


#Show hidden files, folders and drives in File Explorer 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f 


#Show file extensions in File Explorer 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f 


#Launch folder windows in a separate process 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d 1 /f 


#Auto-end non responsive tasks 
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f 


#Maximize wallpaper quality 
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d 100 /f 


#Set icon cache size to 4096 KB 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d "4096" /f 


#Add Recycle Bin to Navigation Pane 
reg add "HKCU\SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 1 /f 


#Restore Classic Context Menu in Explorer 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\FlightedFeatures" /v "ImmersiveContextMenu" /t REG_DWORD /d 0 /f 


#Set "Do this for all current items" checkbox by default in the file operation conflict dialog 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "ConfirmationCheckBoxDoForAll" /t REG_DWORD /d 1 /f 


#Enable NTFS long paths 
reg add "HKLM\SYSTEM\CurrentControlSet\Policies" /v "LongPathsEnabled" /t REG_DWORD /d 1 /f 



#Open Explorer to "This PC"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /d 1 /t "REG_DWORD" /f

#Set UAC
cls
Write-Host "Change UAC to your preference"
Start-Sleep 1;
C:\Windows\System32\UserAccountControlSettings.exe
Start-Sleep 3;


#Disable multicast - DNS client
cls
Write-Host "Disabling multicast - DNS client"
Start-Sleep 3;
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /d 0 /t "REG_DWORD" /f



#Power setting
cls
Write-Host "Setting 'High Performance' power plan and no monitor timeout"
Start-Sleep 3;
powercfg /SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -change -monitor-timeout-ac 0


#Remove the Windows 10 Shit in Windows Firewall
cls
Write-Host "Removing default firewall rules for the Windows 10 apps"
Start-Sleep 3;
Get-NetFirewallRule | Where { $_.Group -like '*@{*' } | Remove-NetFirewallRule
Get-NetFirewallRule | Where { $_.Group -eq 'DiagTrack' } | Remove-NetFirewallRule
Get-NetFirewallRule | Where { $_.DisplayGroup -eq 'Delivery Optimization' } | Remove-NetFirewallRule
Get-NetFirewallRule | Where { $_.DisplayGroup -like 'Windows Media Player Network Sharing Service*' } | Remove-NetFirewallRule
Get-NetFirewallRule | Where { $_.Group -eq 'Your account*' } | Remove-NetFirewallRule
Get-NetFirewallRule | Where { $_.Group -eq 'Work or school account*' } | Remove-NetFirewallRule
Get-NetFirewallRule | Where { $_.DisplayGroup -like '*AllJoyn*' } | Remove-NetFirewallRule
Get-NetFirewallRule | Where { $_.DisplayGroup -like '*Cast*' } | Remove-NetFirewallRule
Get-NetFirewallRule | Where { $_.DisplayGroup -eq 'mDNS' } | Remove-NetFirewallRule
Get-NetFirewallRule | Where { $_.DisplayGroup -like '*Teredo*' } | Remove-NetFirewallRule
Get-NetFirewallRule | Where { $_.Group -like 'Cortana*' } | Remove-NetFirewallRule


#Deativate SeachUI / Cortana
cls
Write-Host "Disabling SearchUI / Cortana"
Start-Sleep 3;
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch" /v Start /d 4 /t "REG_DWORD" /f
cd C:\Windows\SystemApps
cmd.exe /c takeown /f "*" /r /d y 
icacls "*" /grant administrators:F /t
mkdir killed
taskkill /f /im SearchUI.exe 
taskkill /f /im searchindexer.exe
move-item ".\Microsoft*" ".\killed"

cls
Write-Host "The following script is J. G. Spiers"
Write-Host "http://www.jgspiers.com/windows-server-2016-optimisation-script/"
Start-Sleep 5;

#following script is J G Spiers - http://www.jgspiers.com/windows-server-2016-optimisation-script/

<#

####################################################################

#    File Name     : WS2016Optimisations.ps1                       #

#    Author        : George Spiers with thanks to Keith Campbell   #

#                    for assistance.                               #

#    Email         : george@jgspiers.com                           #

#    Twitter       : @JGSpiers                                     #

#    Website       : www.jgspiers.com                              #

#    Date Created  : 15.03.2017                                    #

#    Tested on     : Windows Server 2016 build 14393.0             # 

#    Description   : This script disables services, removes        #

#                    scheduled tasks and imports registry          #

#                    values to optimise system                     #

#                    performance on Windows Server 2016            #

#                    running in a Citrix SBC environment.          #                                                               

#    Warning       : This script makes changes to the system       #

#                    registry and other configurational change     #

#                    and as such a full backup of the machine or   #

#                    snapshot if running in a virtual environment  # 

#                    is strongly recommended. Carry out full       #

#                    testing before introducing image to           #

#                    production.                                   #

#    Note          : You should review ALL optimisations this      #

#                    script makes and determine if they fit in to  #

#                    your environment. Not every optimisation      # 

#                    suits all environments. For example, this     #

#                    script disables key Hyper-V services for use  #

#                    in non-Hyper-V environments. If you use       #

#                    Hyper-V, you must enable these services.      #

#    Instructions  : To avoid failure, run PowerShell as an        #

#                    administrator.                                #
     
#    Change Log    : 15.04.17 - Added registry key to change power #
                                
#                               plan from Balanced to High Perform #
                                
#                               ance.                              #
                     
#                  : 01.06.17 - Added CDPUserSvc_498c4,            #
                                
#                               Contact_Data_498c4,                #
                                
#                               Link-Layer Topology Discovery      #
                                
#                               Mapper, Network Connection Broker, #
                                
#                               Program Compatibility Assistant Se #
                                
#                               rvice, Windows Insider Service to  #
                                
#                               service disable list.              #
                    
#                  : 27.06.17 - Removed line that disabled         #
                                 
#                               Application Readiness service.     #
                                 
#                               Disabling this service caused      #
                                 
#                               an issue with Windows Updates.     #

#                  : 10.07.17 - Changed Disk I/O Timeout vaue from #
                                
#                               65 seconds to 200 seconds. HKLM\   #
                                
#                               SYSTEM\CurrentControlSet\Services\ #
                                
#                               Disk - TimeoutValue.               #

####################################################################

#>



# Set Command Descriptive Text in Cyan

$CommandDesc = " -ForegroundColor Cyan"



function CMDColour($text){

    invoke-expression ("Write-Host " + $text + $CommandDesc)

}



$cmdList =  

	@("", "The following section contains commands that remove Active Setup Registry entries. These optimisations are aimed at reducing logon times.", "sectioncomplete"),

     ("Deleting StubPath - Themes Setup.","'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{2C7339CF-2B09-4501-B3F3-F3508C9228ED}' /v StubPath /f", "delete"),

     ("Deleting StubPath - WinMail.", "'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{44BBA840-CC51-11CF-AAFA-00AA00B6015C}' /v StubPath /f", "delete"),

     ("Deleting StubPath x64 - WinMail.", "'HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\{44BBA840-CC51-11CF-AAFA-00AA00B6015C}' /v StubPath /f", "delete"),

     ("Deleting StubPath - Windows Media Player.", "'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}' /v StubPath /f", "delete"),

     ("Deleting StubPath x64 - Windows Media Player.", "'HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}' /v StubPath /f", "delete"),

     ("Deleting StubPath - Windows Desktop Update.", "'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4340}' /v StubPath /f", "delete"),

     ("Deleting StubPath - Web Platform Customizations.", "'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4383}' /v StubPath /f", "delete"),

     ("Deleting StubPath - DotNetFrameworks.", "'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{89B4C1CD-B018-4511-B0A1-5476DBF70820}' /v StubPath /f", "delete"),

     ("Deleting StubPath x64 - DotNetFrameworks.", "'HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\{89B4C1CD-B018-4511-B0A1-5476DBF70820}' /v StubPath /f", "delete"),

     ("Deleting StubPath - Windows Media Player.", "'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\>{22d6f312-b0f6-11d0-94ab-0080c74c7e95}' /v StubPath /f", "delete"),

     ("Deleting StubPath x64 - Windows Media Player.", "'HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\>{22d6f312-b0f6-11d0-94ab-0080c74c7e95}' /v StubPath /f", "delete"),

     ("Deleting StubPath - IE ESC for Admins.", "'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' /v StubPath /f", "delete"),

     ("Deleting StubPath - IE ESC for Users.", "'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' /v StubPath /f", "delete"),

     ("", "The following section contains commands that add or modify various Registry entries to the system. These optimisations are aimed at improving system performance. Many of these optimisations are the same ones you get when running the PVS 7.11 Target Device Optimization Tool with the exception of HKCU optimizations. Optimizations made by importing HKCU registry entries should be created via Group Policy or Citrix WEM.", "sectioncomplete"),

	 ("Modifying DisablePagingExecutive DWORD from 0x0 to 0x1 - Keep drivers and kernel on physical memory.", "'HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management' /v DisablePagingExecutive /t REG_DWORD /d 0x1 /f", "add"),

     ("Modifying EventLog DWORD from 0x3 to 0x1 - Log print job error notifications in Event Viewer.", "'HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers' /v EventLog /t REG_DWORD /d 0x1 /f", "add"),

     ("Adding DisableTaskOffload DWORD - Disable Task Offloading.", "'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' /v DisableTaskOffload /t REG_DWORD /d 0x1 /f", "add"),

     ("Adding HideSCAHealth DWORD - Hide Action Center Icon.", "'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v HideSCAHealth /t REG_DWORD /d 0x1 /f", "add"),

     ("Adding NoRemoteRecursiveEvents DWORD - Turn off change notify events for file and folder changes.", "'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v NoRemoteRecursiveEvents /t REG_DWORD /d 0x1 /f", "add"),

     ("Adding SendAlert DWORD - Do not send Administrative alert during system crash.", "'HKLM\SYSTEM\CurrentControlSet\Control\CrashControl' /v SendAlert /t REG_DWORD /d 0x0 /f", "add"),

     ("Modifying CrashDumpEnabled DWORD from 0x7 to 0x0 - Disable crash dump creation.", "'HKLM\SYSTEM\CurrentControlSet\Control\CrashControl' /v CrashDumpEnabled /t REG_DWORD /d 0x0 /f", "add"),

     ("Modifying LogEvent DWORD from 0x1 to 0x0 - Disable system crash logging to Event Log.", "'HKLM\SYSTEM\CurrentControlSet\Control\CrashControl' /v LogEvent /t REG_DWORD /d 0x0 /f", "add"),

     ("Modifying ErrorMode DWORD from 0x0 to 0x2 - Hide hard error messages.", "'HKLM\SYSTEM\CurrentControlSet\Control\Windows' /v ErrorMode /t REG_DWORD /d 0x2 /f", "add"),

     ("Adding ShowTray DWORD - Hide VMware Tools tray icon.", "'HKLM\SOFTWARE\VMware, Inc.\VMware Tools' /v ShowTray /t REG_DWORD /d 0x0 /f", "add"),

     ("Modifying Application REG_EXPAND_SZ from default location to D:\ - Move Application Event Log from default location to D:\.", "'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application' /v File /t REG_EXPAND_SZ /d 'D:\Event Logs\Application.evtx' /f", "add"),

     ("Modifying Security REG_EXPAND_SZ from default location to D:\ - Move Security Event Log from default location to D:\.", "'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security' /v File /t REG_EXPAND_SZ /d 'D:\Event Logs\Security.evtx' /f", "add"),

     ("Modifying System REG_EXPAND_SZ from default location to D:\ - Move System Event Log from default location to D:\.", "'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System' /v File /t REG_EXPAND_SZ /d 'D:\Event Logs\System.evtx' /f", "add"),

     ("Adding ServicesPipeTimeout DWORD - Increase services startup timeout from 30 to 45 seconds.", "'HKLM\SYSTEM\CurrentControlSet\Control' /v ServicesPipeTimeout /t REG_DWORD /d 0xafc8 /f", "add"),

     ("Adding DisableFirstRunCustomize DWORD - Disable Internet Explorer first-run customise wizard.", "'HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' /v DisableFirstRunCustomize /t REG_DWORD /d 0x1 /f", "add"),

     ("Adding AllowTelemetry DWORD - Disable telemetry.", "'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v AllowTelemetry /t REG_DWORD /d 0x0 /f", "add"),

	 ("Adding Enabled DWORD - Disable offline files.", "'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache' /v Enabled /t REG_DWORD /d 0x0 /f", "add"),

     ("Adding Enable REG_SZ - Disable Defrag.", "'HKLM\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction' /v Enable /t REG_SZ /d N /f", "add"),

     ("Changing NtfsDisableLastAccessUpdate DWORD to 0x1 - Disable last access timestamp.", "'HKLM\SYSTEM\CurrentControlSet\FileSystem' /v NtfsDisableLastAccessUpdate /t REG_DWORD /d 0x1 /f", "add"),

     ("Changing MaxSize DWORD from 0x01400000 to 0x00010000 - Reduce Application Event Log size to 64KB.", "'HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Application' /v MaxSize /t REG_DWORD /d 0x10000 /f", "add"),

     ("Changing MaxSize DWORD from 0x0140000 to 0x00010000 - Reduce Security Event Log size to 64KB.", "'HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security' /v MaxSize /t REG_DWORD /d 0x10000 /f", "add"),

     ("Changing MaxSize DWORD from 0x0140000 to 0x00010000 - Reduce Security Event Log size to 64KB.", "'HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security' /v MaxSize /t REG_DWORD /d 0x10000 /f", "add"),

     ("Changing MaxSize DWORD from 0x0140000 to 0x00010000 - Reduce System Event Log size to 64KB.", "'HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\System' /v MaxSize /t REG_DWORD /d 0x10000 /f", "add"),

     ("Changing ClearPageFileAtShutdown DWORD to 0x0 - Disable clear Page File at shutdown.", "'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' /v NtfsDisableLastAccessUpdate /t REG_DWORD /d 0x0 /f", "add"),

     ("Creating NoAutoUpdate DWORD - Disable Windows Autoupdate.", "'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' /v NoAutoUpdate /t REG_DWORD /d 0x1 /f", "add"),

     ("Creating AUOptions DWORD - Disable Windows Autoupdate.", "'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' /v AUOptions /t REG_DWORD /d 0x1 /f", "add"),

     ("Creating ScheduleInstallDay DWORD - Disable Windows Autoupdate.", "'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' /v ScheduleInstallDay /t REG_DWORD /d 0x0 /f", "add"),

     ("Creating ScheduleInstallTime DWORD - Disable Windows Autoupdate.", "'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' /v ScheduleInstallTime /t REG_DWORD /d 0x3 /f", "add"),

     ("Creating EnableAutoLayout DWORD - Disable Background Layout Service.", "'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout' /v EnableAutoLayout /t REG_DWORD /d 0x0 /f", "add"),

     ("Creating DumpFileSize DWORD - Reduce DedicatedDumpFile DumpFileSize to 2 MB.", "'HKLM\SYSTEM\CurrentControlSet\Control\CrashControl' /v DumpFileSize /t REG_DWORD /d 0x2 /f", "add"),

     ("Creating IgnorePagefileSize DWORD - Reduce DedicatedDumpFile DumpFileSize to 2 MB.", "'HKLM\SYSTEM\CurrentControlSet\Control\CrashControl' /v IgnorePagefileSize /t REG_DWORD /d 0x1 /f", "add"),

     ("Creating Paths DWORD - Reduce IE Temp File.", "'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths' /v Paths /t REG_DWORD /d 0x4 /f", "add"),

     ("Creating CacheLimit DWORD - Reduce IE Temp File.", "'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths\path1' /v CacheLimit /t REG_DWORD /d 0x100 /f", "add"),

     ("Creating CacheLimit DWORD - Reduce IE Temp File.", "'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths\path2' /v CacheLimit /t REG_DWORD /d 0x100 /f", "add"),

     ("Creating CacheLimit DWORD - Reduce IE Temp File.", "'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths\path3' /v CacheLimit /t REG_DWORD /d 0x100 /f", "add"),

     ("Creating CacheLimit DWORD - Reduce IE Temp File.", "'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths\path4' /v CacheLimit /t REG_DWORD /d 0x100 /f", "add"),

     ("Adding DisableLogonBackgroundImage DWORD - Disable Logon Background Image.", "'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v DisableLogonBackgroundImage /t REG_DWORD /d 0x1 /f", "add"),
     
     ("Changing DisablePasswordChange DWORD from 0x0 to 0x1 - Disable Machine Account Password Changes.", "'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' /v DisablePasswordChange /t REG_DWORD /d 0x1 /f", "add"),

     ("Changing PreferredPlan REG_SZ from 381b4222-f694-41f0-9685-ff5bb260df2e to 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c - Changing Power Plan to High Performance.", "'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{025A5937-A6BE-4686-A844-36FE4BEC8B6D}' /v PreferredPlan /t REG_SZ /d 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c /f", "add"),

     ("Changing TimeoutValue DWORD from 0x41 to 0xC8 - Increase Disk I/O Timeout to 200 seconds .", "'HKLM\SYSTEM\CurrentControlSet\Services\Disk' /v TimeoutValue /t REG_DWORD /d 0xC8 /f", "add"),

     ("", "The following section contains commands that disable services. These optimisations are aimed at reducing system footprint and improving performance.", "sectioncomplete"),

	 ("Disabling service AJRouter - AllJoyn Router Service.", "AJRouter -StartupType Disabled", "set-service"),

     ("Disabling service ALG - Application Layer Gateway Service.", "ALG -StartupType Disabled", "set-service"),

     ("Disabling service AppMgmt - Application Management.", "AppMgmt -StartupType Disabled", "set-service"),

     ("Disabling service bthserv - Bluetooth Support Service.", "bthserv -StartupType Disabled", "set-service"),

     ("Disabling service CDPUserSvc_498c4 - CDPUserSvc_498c4.", "CDPUserSvc_498c4 -StartupType Disabled", "set-service"),

     ("Disabling service PimIndexMaintenanceSvc_498c4 - Contact_Data_498c4.", "PimIndexMaintenanceSvc_498c4 -StartupType Disabled", "set-service"),

     ("Disabling service DcpSvc - DataCollectionPublishingService.", "DcpSvc -StartupType Disabled", "set-service"),

     ("Disabling service DPS - Diagnostic Policy Service.", "DPS -StartupType Disabled", "set-service"),

     ("Disabling service WdiServiceHost - Diagnostic Service Host.", "WdiServiceHost -StartupType Disabled", "set-service"),

     ("Disabling service WdiSystemHost - Diagnostic System Host.", "WdiSystemHost -StartupType Disabled", "set-service"),

     ("Disabling service DiagTrack - Connected User Experiences and Telemetry [Diagnostics Tracking Service].", "DiagTrack -StartupType Disabled", "set-service"),

     ("Disabling service dmwappushservice - dmwappushsvc.", "dmwappushservice -StartupType Disabled", "set-service"),

     ("Disabling service MapsBroker - Downloaded Maps Manager.", "MapsBroker -StartupType Disabled", "set-service"),

     ("Disabling service EFS - Encrypting File System [EFS].", "EFS -StartupType Disabled", "set-service"),

     ("Disabling service Eaphost - Extensible Authentication Protocol.", "Eaphost -StartupType Disabled", "set-service"),

     ("Disabling service FDResPub - Function Discovery Resource Publication.", "FDResPub -StartupType Disabled", "set-service"),

     ("Disabling service lfsvc - Geolocation Service.", "lfsvc -StartupType Disabled", "set-service"),

     ("Disabling service HvHost - HV Host Service.", "HvHost -StartupType Disabled", "set-service"),

     ("Disabling service vmickvpexchange - Hyper-V Data Exchange Service.", "vmickvpexchange -StartupType Disabled", "set-service"),

     ("Disabling service vmicguestinterface - Hyper-V Guest Service Interface.", "vmicguestinterface -StartupType Disabled", "set-service"),

     ("Disabling service vmicshutdown - Hyper-V Guest Shutdown Interface.", "vmicshutdown -StartupType Disabled", "set-service"),

     ("Disabling service vmicheartbeat - Hyper-V Heartbeat Service.", "vmicheartbeat -StartupType Disabled", "set-service"),

     ("Disabling service vmicvmsession - Hyper-V PowerShell Direct Service.", "vmicvmsession -StartupType Disabled", "set-service"),

     ("Disabling service vmicrdv - Hyper-V Remote Desktop Virtualization Service.", "vmicrdv -StartupType Disabled", "set-service"),

     ("Disabling service vmictimesync - Hyper-V Time Synchronization Service.", "vmictimesync -StartupType Disabled", "set-service"),

     ("Disabling service vmicvss - Hyper-V Volume Shadow Copy Requestor.", "vmicvss -StartupType Disabled", "set-service"),

     ("Disabling service UI0Detect - Interactive Services Detection.", "UI0Detect -StartupType Disabled", "set-service"),

     ("Disabling service SharedAccess - Internet Connection Sharing [ICS].", "SharedAccess -StartupType Disabled", "set-service"),

     ("Disabling service iphlpsvc - IP Helper.", "iphlpsvc -StartupType Disabled", "set-service"),

     ("Disabling service ltdsvc - Link-Layer Topology Discovery Mapper.", "ltdsvc -StartupType Disabled", "set-service"),

     ("Disabling service diagnosticshub.standardcollector.service - Microsoft [R] Diagnostics Hub Standard Collector Service.", "diagnosticshub.standardcollector.service -StartupType Disabled", "set-service"),

     ("Disabling service wlidsvc - Microsoft Account Sign-in Assistant.", "wlidsvc -StartupType Disabled", "set-service"),

     ("Disabling service MSiSCSI - Microsoft iSCSI Initiator Service.", "MSiSCSI -StartupType Disabled", "set-service"),

     ("Disabling service smphost - Microsoft Storage Spaces SMP.", "smphost -StartupType Disabled", "set-service"),

     ("Disabling service NcbService - Network Connection Broker.", "NcbService -StartupType Disabled", "set-service"),

     ("Disabling service NcaSvc - Network Connectivity Assistant.", "NcaSvc -StartupType Disabled", "set-service"),

     ("Disabling service defragsvc - Optimize drives.", "defragsvc -StartupType Disabled", "set-service"),

     ("Disabling service wercplsupport - Problem Reports and Solutions Control Panel.", "wercplsupport -StartupType Disabled", "set-service"),

     ("Disabling service PcaSvc - Program Compatibility Assistant Service.", "PcaSvc -StartupType Disabled", "set-service"),

     ("Disabling service QWAVE - Quality Windows Audio Video Experience.", "QWAVE -StartupType Disabled", "set-service"),

     ("Disabling service RmSvc - Radio Management Service.", "RmSvc -StartupType Disabled", "set-service"),

     ("Disabling service RasMan - Remote Access Connection Manager.", "RasMan -StartupType Disabled", "set-service"),

     ("Disabling service SstpSvc - Secure Socket Tunneling Protocol Service.", "SstpSvc -StartupType Disabled", "set-service"),

     ("Disabling service SensorDataService - Sensor Data Service.", "SensorDataService -StartupType Disabled", "set-service"),

     ("Disabling service SensrSvc - Sensor Monitoring Service.", "SensrSvc -StartupType Disabled", "set-service"),

     ("Disabling service SensorService - Sensor Service.", "SensorService -StartupType Disabled", "set-service"),

     ("Disabling service SNMPTRAP - SNMP Trap.", "SNMPTRAP -StartupType Disabled", "set-service"),

     ("Disabling service sacsvr - Special Administration Console Helper.", "sacsvr -StartupType Disabled", "set-service"),

     ("Disabling service svsvc - Spot Verifier.", "svsvc -StartupType Disabled", "set-service"),

     ("Disabling service SSDPSRV - SSDP Discovery.", "SSDPSRV -StartupType Disabled", "set-service"),

     ("Disabling service TieringEngineService - Storage Tiers Management.", "TieringEngineService -StartupType Disabled", "set-service"),

     ("Disabling service SysMain - Superfetch.", "SysMain -StartupType Disabled", "set-service"),

     ("Disabling service TapiSrv - Telephony.", "TapiSrv -StartupType Disabled", "set-service"),

     ("Disabling service UALSVC - User Access Logging Service.", "UALSVC -StartupType Disabled", "set-service"),

     ("Disabling service WerSvc - Windows Error Reporting Service.", "WerSvc -StartupType Disabled", "set-service"),

     ("Disabling service wisvc - Windows Insider Service.", "wisvc -StartupType Disabled", "set-service"),

     ("Disabling service icssvc - Windows Mobile Hotspot Service.", "icssvc -StartupType Disabled", "set-service"),

     ("Disabling service wuauserv - Windows Update.", "wuauserv -StartupType Disabled", "set-service"),

     ("Disabling service dot3svc - Wired AutoConfig.", "dot3svc -StartupType Disabled", "set-service"),

     ("Disabling service XblAuthManager - Xbox Live Auth Manager.", "XblAuthManager -StartupType Disabled", "set-service"),

     ("Disabling service XblGameSave - Xbox Live Game Save.", "XblGameSave -StartupType Disabled", "set-service"),

     ("", "The following section contains commands that delete Scheduled Tasks. These optimisations are aimed at reducing system footprint and improving performance.", "sectioncomplete"),

	 ("Disabling Scheduled Task - Policy Template Management [Manual].", "-TaskName 'AD RMS Rights Policy Template Management (Manual)' -TaskPath '\Microsoft\Windows\Active Directory Rights Management Services Client'", "Disable-ScheduledTask"),

	 ("Disabling Scheduled Task - EDP Policy Manager.", "-TaskName 'EDP Policy Manager' -TaskPath '\Microsoft\Windows\AppID'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - SmartScreenSpecific.", "-TaskName 'SmartScreenSpecific' -TaskPath '\Microsoft\Windows\AppID'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Microsoft Compatibility Appraiser.", "-TaskName 'Microsoft Compatibility Appraiser' -TaskPath '\Microsoft\Windows\Application Experience'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - ProgramDataUpdater.", "-TaskName 'ProgramDataUpdater' -TaskPath '\Microsoft\Windows\Application Experience'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - StartupAppTask.", "-TaskName 'StartupAppTask' -TaskPath '\Microsoft\Windows\Application Experience'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - CleanupTemporaryState.", "-TaskName 'CleanupTemporaryState' -TaskPath '\Microsoft\Windows\ApplicationData'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - DsSvcCleanup.", "-TaskName 'DsSvcCleanup' -TaskPath '\Microsoft\Windows\ApplicationData'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Proxy.", "-TaskName 'Proxy' -TaskPath '\Microsoft\Windows\Autochk'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - UninstallDeviceTask.", "-TaskName 'UninstallDeviceTask' -TaskPath '\Microsoft\Windows\Bluetooth'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - AikCertEnrollTask.", "-TaskName 'AikCertEnrollTask' -TaskPath '\Microsoft\Windows\CertificateServicesClient'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - CryptoPolicyTask.", "-TaskName 'CryptoPolicyTask' -TaskPath '\Microsoft\Windows\CertificateServicesClient'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - KeyPreGenTask.", "-TaskName 'KeyPreGenTask' -TaskPath '\Microsoft\Windows\CertificateServicesClient'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - ProactiveScan.", "-TaskName 'ProactiveScan' -TaskPath '\Microsoft\Windows\Chkdsk'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - CreateObjectTask.", "-TaskName 'CreateObjectTask' -TaskPath '\Microsoft\Windows\CloudExperienceHost'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Consolidator.", "-TaskName 'Consolidator' -TaskPath '\Microsoft\Windows\Customer Experience Improvement Program'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - KernelCeipTask.", "-TaskName 'KernelCeipTask' -TaskPath '\Microsoft\Windows\Customer Experience Improvement Program'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - UsbCeipr.", "-TaskName 'UsbCeip' -TaskPath '\Microsoft\Windows\Customer Experience Improvement Program'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Data Integrity Scan.", "-TaskName 'Data Integrity Scan' -TaskPath '\Microsoft\Windows\Data Integrity Scan'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Data Integrity Scan for Crash Recovery.", "-TaskName 'Data Integrity Scan for Crash Recovery' -TaskPath '\Microsoft\Windows\Data Integrity Scan'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - ScheduledDefrag.", "-TaskName 'ScheduledDefrag' -TaskPath '\Microsoft\Windows\Defrag'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Device.", "-TaskName 'Device' -TaskPath '\Microsoft\Windows\Device Information'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Scheduled.", "-TaskName 'Scheduled' -TaskPath '\Microsoft\Windows\Diagnosis'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - SilentCleanup.", "-TaskName 'SilentCleanup' -TaskPath '\Microsoft\Windows\DiskCleanup'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Microsoft-Windows-DiskDiagnosticDataCollector.", "-TaskName 'Microsoft-Windows-DiskDiagnosticDataCollector' -TaskPath '\Microsoft\Windows\DiskDiagnostic'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Notifications.", "-TaskName 'Notifications' -TaskPath '\Microsoft\Windows\Location'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - WindowsActionDialog.", "-TaskName 'WindowsActionDialog' -TaskPath '\Microsoft\Windows\Location'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - WinSAT.", "-TaskName 'WinSAT' -TaskPath '\Microsoft\Windows\Maintenance'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - MapsToastTask.", "-TaskName 'MapsToastTask' -TaskPath '\Microsoft\Windows\Maps'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - MNO Metadata Parser.", "-TaskName 'MNO Metadata Parser' -TaskPath '\Microsoft\Windows\Mobile Broadband Accounts'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - LPRemove.", "-TaskName 'LPRemove' -TaskPath '\Microsoft\Windows\MUI'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - GatherNetworkInfo.", "-TaskName 'GatherNetworkInfo' -TaskPath '\Microsoft\Windows\NetTrace'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Secure-Boot-Update.", "-TaskName 'Secure-Boot-Update' -TaskPath '\Microsoft\Windows\PI'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Sqm-Tasks.", "-TaskName 'Sqm-Tasks' -TaskPath '\Microsoft\Windows\PI'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - AnalyzeSystem.", "-TaskName 'AnalyzeSystem' -TaskPath '\Microsoft\Windows\Power Efficiency Diagnostics'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - MobilityManager.", "-TaskName 'MobilityManager' -TaskPath '\Microsoft\Windows\Ras'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - VerifyWinRE.", "-TaskName 'VerifyWinRE' -TaskPath '\Microsoft\Windows\RecoveryEnvironment'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - RegIdleBackup.", "-TaskName 'RegIdleBackup' -TaskPath '\Microsoft\Windows\Registry'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - CleanupOldPerfLogs.", "-TaskName 'CleanupOldPerfLogs' -TaskPath '\Microsoft\Windows\Server Manager'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - StartComponentCleanup.", "-TaskName 'StartComponentCleanup' -TaskPath '\Microsoft\Windows\Servicing'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - IndexerAutomaticMaintenance.", "-TaskName 'IndexerAutomaticMaintenance' -TaskPath '\Microsoft\Windows\Shell'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Configuration.", "-TaskName 'Configuration' -TaskPath '\Microsoft\Windows\Software Inventory Logging'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - SpaceAgentTask.", "-TaskName 'SpaceAgentTask' -TaskPath '\Microsoft\Windows\SpacePort'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - SpaceManagerTask.", "-TaskName 'SpaceManagerTask' -TaskPath '\Microsoft\Windows\SpacePort'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - SpeechModelDownloadTask.", "-TaskName 'SpeechModelDownloadTask' -TaskPath '\Microsoft\Windows\Speech'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Storage Tiers Management Initialization.", "-TaskName 'Storage Tiers Management Initialization' -TaskPath '\Microsoft\Windows\Storage Tiers Management'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Tpm-HASCertRetr.", "-TaskName 'Tpm-HASCertRetr' -TaskPath '\Microsoft\Windows\TPM'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Tpm-Maintenance.", "-TaskName 'Tpm-Maintenance' -TaskPath '\Microsoft\Windows\TPM'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Schedule Scan.", "-TaskName 'Schedule Scan' -TaskPath '\Microsoft\Windows\UpdateOrchestrator'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - ResolutionHost.", "-TaskName 'ResolutionHost' -TaskPath '\Microsoft\Windows\WDI'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - QueueReporting.", "-TaskName 'QueueReporting' -TaskPath '\Microsoft\Windows\Windows Error Reporting'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Automatic App Update.", "-TaskName 'Automatic App Update' -TaskPath '\Microsoft\Windows\WindowsUpdate'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - Scheduled Start.", "-TaskName 'Scheduled Start' -TaskPath '\Microsoft\Windows\WindowsUpdate'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - sih.", "-TaskName 'sih' -TaskPath '\Microsoft\Windows\WindowsUpdate'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - sihboot.", "-TaskName 'sihboot' -TaskPath '\Microsoft\Windows\WindowsUpdate'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - XblGameSaveTask.", "-TaskName 'XblGameSaveTask' -TaskPath '\Microsoft\XblGameSave'", "Disable-ScheduledTask"),

     ("Disabling Scheduled Task - XblGameSaveTaskLogon.", "-TaskName 'XblGameSaveTaskLogon' -TaskPath '\Microsoft\XblGameSave'", "Disable-ScheduledTask"),

     ("", "The following section contains a command that removes the Windows Defender feature. This action also removes Scheduled Tasks and services relating to Windows Defender. This optimisation is based on the assumption that another antivirus will be used to replace Windows Defender.", "sectioncomplete"),

	 ("Removing WindowsFeature Windows-Defender-Features", "Windows-Defender-Features", "Remove-WindowsFeature");



# Pause for 2 Seconds between Commands

$Pausefor2Secs = "Start-Sleep 0"



# Pause for 5 Seconds between Descriptions

$Pausefor5Secs = "Start-Sleep 5"



Foreach ($cmd in $cmdList) {



	# Print description of change

	CMDColour $cmd[0]



	#Identify type of change

	switch($cmd[2]) {

	

        "sectioncomplete"

            {

                Write-Host $cmd[1] -ForeGroundColor Green

                Invoke-Expression $Pausefor5Secs

            }		



        "delete" # The following "reg delete" section will run commands that remove Active Setup Registry entries. These optimisations are aimed at reducing logon times.

			{

				Write-Host "reg delete" $cmd[1]

				Invoke-Expression ("reg delete " + $cmd[1])



                Invoke-Expression $Pausefor2Secs

			}

			

		"add" # The following section contains commands that add various Registry entries to the system. These optimisations are aimed at improving system performance. Many of these optimisations are the same ones you get when running the PVS 7.11 Target Device Optimization Tool with the exception of HKCU optimizations. Optimizations made by importing HKCU registry entries should be created via Group Policy or Citrix WEM.

              # Optimisations that the Target Device Optimization Tool makes but are left out in this script:

              # - Disable Indexing Service - Redundant, replaced by Windows Search. Windows Search not installed by default on WS2016.

              # - Disable Windows SuperFetch service - This service is set to be disabled already further down this script.

              # - Disable Windows Search - Windows Search is not installed by default on WS2016.

			{

				Write-Host "reg add" $cmd[1]

				Invoke-Expression ("reg add " + $cmd[1])



                Invoke-Expression $Pausefor2Secs

			}

	

		"set-service" # The following "Set-Service" section will run commands that disable services. These optimisations are aimed at reducing system footprint and improving performance.

			{

				Write-Host "Set-Service" $cmd[1]

				Invoke-Expression ("Set-Service " + $cmd[1])



                Invoke-Expression $Pausefor2Secs

			}

	

		"Disable-ScheduledTask" #The following "Disable ScheduledTask" section will run commands that Scheduled Tasks. These optimisations are aimed at reducing system footprint and improving performance.

			{

				Write-Host "Disable-ScheduledTask" $cmd[1]

				Invoke-Expression ("Disable-ScheduledTask " + $cmd[1])



                Invoke-Expression $Pausefor2Secs

			}

			

		"Remove-WindowsFeature" # The following "Remote-WindowsFeature" section will run a command that removes the Windows Defender feature. This action also removes Scheduled Tasks and services relating to Windows Defender. This optimisation is based on the assumption that another antivirus will be used to replace Windows Defender.

			                    # Windows Scheduled Tasks removed after removal of Windows Defender:

                                # - Windows Defender Cache Maintenance

                                # - Windows Defender Cleanup

                                # - Windows Defender Scheduled Scan

                                # - Windows Defender Verification

                                # Windows services removed after removal of Windows Defender:

                                # - Windows Defender Network Inspection Service

                                # - Windws Defender Service

            {

				Write-Host "Remove-WindowsFeature" $cmd[1]

				Invoke-Expression ("Remove-WindowsFeature " + $cmd[1])

			}

			

	} # End of Switch

} # End of Foreach



	

Write-Host "All optimisations complete. Please restart your system." -ForegroundColor Green
