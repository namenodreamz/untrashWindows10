Function DisableCortana
{
    
}

Function smallIconSize
{
    Set-ItemProperty -path HKCU:\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop -name IconSize -value 36
    Stop-Process -name explorer #Restart explorer.exe
}

Function removeUnusedApps
{
    Get-AppxPackage Microsoft.3DBuilder | Remove-AppxPackage
    Get-AppxPackage Microsoft.ZuneMusic | Remove-AppxPackage  #Groove
    #Get-AppxPackage Microsoft.BioEnrollment | Remove-AppxPackage # Error Needs to be Administrator?
    Get-AppxPackage Microsoft.People | Remove-AppxPackage
    Get-AppxPackage Microsoft.BingWeather | Remove-AppxPackage  
    Get-AppxPackage Microsoft.WindowsMaps | Remove-AppxPackage
    Get-AppxPackage Microsoft.Windows.Photos | Remove-AppxPackage 
    Get-AppxPackage Microsoft.MicrosoftSolitaireCollection | Remove-AppxPackage 
    Get-AppxPackage Microsoft.MicrosoftStickyNotes | Remove-AppxPackage 
    Get-AppxPackage Microsoft.Office.OneNote | Remove-AppxPackage
    Get-AppxPackage Microsoft.MicrosoftOfficeHub | Remove-AppxPackage
    Get-AppxPackage Microsoft.XboxIdentityProvider | Remove-AppxPackage
    #Get-AppxPackage Microsoft.XboxGameCallableUI | Remove-AppxPackage  #Mit admin rechten oder feature
    Get-AppxPackage Microsoft.WindowsMaps | Remove-AppxPackage
    Get-AppxPackage Microsoft.Getstarted | Remove-AppxPackage
    Get-AppxPackage Microsoft.WindowsSoundRecorder | Remove-AppxPackage
    Get-AppxPackage Microsoft.WindowsCamera | Remove-AppxPackage
    Get-AppxPackage Microsoft.WindowsAlarms | Remove-AppxPackage
    Get-AppxPackage Microsoft.SkypeApp | Remove-AppxPackage
    Get-AppxPackage microsoft.windowscommunicationsapps | Remove-AppxPackage
    Get-AppxPackage Microsoft.Windows.Photos | Remove-AppxPackage
    #Get-AppxPackage Windows.ContactSupport | Remove-AppxPackage #Admin oder feature
    Get-AppxPackage Microsoft.XboxApp | Remove-AppxPackage
    Get-AppxPackage Microsoft.ZuneVideo | Remove-AppxPackage
    Get-AppxPackage Microsoft.LockApp | Remove-AppxPackage 
    Get-AppxPackage 'feedback' | Remove-AppxPackage
    Get-AppxPackage  Microsoft.WindowsFeedbackHub | Remove-AppxPackage
    Get-AppxPackage  Microsoft.Messsaging | Remove-AppxPackage
    
}

#untestet
Function setTelemetrieSettings
{
	#Set Telemetry Level to lowest Settings
	Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection\ -name AllowTelemetry -Value 0
	#Deactovate Telemetry Service and ETW-Sessions
	Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack\ -name Start -Value 4
	Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener\ -nameStart -Value 0
	#deactivate wuauserver #only if WSUS server is available
	#Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv\ -name Start -Value 4
	
	
	#Set Firewall Rule to block DiagTrack 
	
	# Besitzer der Datei aendern
	$Account = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList 'VORDEFINIERT\Administratoren';
	$ACL = $null
	$ACL = Get-Acl -Path C:\Windows\System32\svchost.exe
	$ACL.SetOwner($Account)
	Set-Acl -Path C:\Windows\System32\svchost.exe -AclObject $ACL
	# Abfrage der Access Control Liste
	$ACL = $null
	$ACL = Get-Acl C:\Windows\System32\svchost.exe
	# Zugriffsrechte setzen
	$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule($Account, "Write", "Allow")
	$ACL.SetAccessRule($Ar)
	Set-Acl C:\Windows\System32\svchost.exe $ACL
	# Wechsle in Zielverzeichnis
	Set-Location -Path C:\Windows\System32\
	# Erstellung Hardlink
	New-Item -ItemType hardlink -Name hard.exe -Value .\svchost.exe
	
	# Anpassung der Registry
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack" -Name "ImagePath" -Value "%SystemRoot%\System32\hard.exe -k utcsvc"
	# Hinzufuegen der Firewall Regel
	New-NetFirewallRule -DisplayName "Block_Diagtrack" -Name "Block_Diagtrack" -Direction Outbound -Program "%SystemRoot%\System32\hard.exe"
	
	#New-NetFirewallRule -DisplayName "BlockDiagTrack" -Name "BlockDiagTrack" -Direction Outbound -Program "%SystemRoot%\System32\utc_myhost.exe" -Action block
	
	
	#Block DNS Adresses für Telemetry
	#Add-Content $env:SystemRoot\System32\drivers\etc "0.0.0.0 geo.settings-win.data.microsoft.com.akadns.net" #throws "wurde verweigert" at the moment
	
	
	
	
}

#Remove One Drive Completely
Functoin removeOneDrive
{
    Write-Host "RemoveOneDrive" -ForegroundColor Black -BackgroundColor White
    Write-Host "Kill OneDrive Task"
    taskkill.exe /F /IM OneDrive.exe #One Drive beenden
    
    Write-Host "Deinstall OneDrive"
    #64 bit
    if(Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe"){
        & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
    }
    #32 bit
    if(Test-Path "$env:systemroot\System32\OneDriveSetup.exe"){
        & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
    }

    Write-Host "Disable OneDrive via Group Policy"
    $keyPath = "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\OneDrive\"
    $key = "DisableFileSyncNGSC"
    $value = 1
    #If Folder does not exist create it 
    if(!(Test-Path $keyPath)){
        New-Item -path $keyPath
        New-ItemProperty -path $keyPath -name $key -value $value
    }
    else {
        Set-ItemProperty -path $keyPath -name $key -value $value
    }
    
    
    Write-Host "Remove OneDrive files left on Disk"
    Remove-Item -Path $env:LOCALAPPDATA\Microsoft\OneDrive -Force -Recurse
    Remove-Item -Path "$env:programdata\Microsoft OneDrive" -Force -Recurse
    
    
    
    
    
    
    #Restart Explorer
    Stop-Process -name explorer #Restart explorer.exe

}

#smallIconSize
removeUnusedApps


