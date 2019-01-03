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


