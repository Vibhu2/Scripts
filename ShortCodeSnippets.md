
<h1 align="Center";p style="color:blue";>My collection of Powershell Snippets </h1>

1.**To get last boot time of the machine**.

```powershell
   (get-date) - (Get-ComputerInfo).OsLastBootUpTime
```

or

```powershell
      (Get-ComputerInfo).OsLastBootUpTime       
```

or

```powershell
      (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
      
```

2.**To get list of stopped services**.

```Powershell
   Get-Service | Where-Object {$_.Status -eq "Stopped" -and $_.Starttype -eq "Automatic"}
```

3.**Setting execution Policy on machine**.

```Powershell
   Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```

4.**Find Drive space**.

```Powershell
   Get-PSDrive -PSProvider FileSystem
```

5.Get Free Space for System Drive.

```Powershell
(Get-PSDrive $Env:SystemDrive.Trim(':')).Free/1GB
```

6.Check BIOS information.

```powershell
(Get-CimInstance Win32_BIOS)
```

7.Check computer information

```powershell
Get-CimInstance Win32_ComputerSystem 
```

8.Check printer information on a machine.

```powershell
 Get-CimInstance Win32_Printer | Select-Object Name, PortName, Default | Format-List
```

9.**Keep System Awake ( VB ) Script**.

```vbs
 set wsc = CreateObject("WScript.Shell")
Do
    'Five minutes
    WScript.Sleep(5*60*1000)
    wsc.SendKeys("{F13}")
Loop
```

10.Install Powershell using chocolaty.

```Powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

choco install powershell -force --yes
choco install powershell-core -force --yes
Start-Sleep -Seconds 90
exit
exit
```

11.Installing winget on a machine using command line.

```powershell
invoke-webrequest
```

12.Checking who rebooted a production server.

```Powershell
Get-EventLog –Log System –Newest 100 | Where-Object {$_.EventID –eq ‘1074’} | FT MachineName, UserName, TimeGenerated -AutoSize
```

14.check Computer domain

```powershell
(Get-CimInstance Win32_ComputerSystem).Domain
```

15.Restart LTServices.

   ```powershell
   Restart-Service -Name ltsvcmon
   Restart-Service -Name labvnc
   Restart-Service -Name ltservice
   Stop-Process -Name ltsvcmon.exe -Force
   Stop-Process -Name ltsvc.exe -Force
   Stop-Process -Name lttray.exe -Force
   Stop-Process -Name labvnc.exe -Force
   Stop-Process -Name labtechupdate.exe -Force
   ```  

16.Enable Remote Desktop using PowerShell

   ```Powershell
   Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
   Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
   exit
```

17.Disable Remote Desktop using PowerShell

   ```powershell
   Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 1
   Disable-NetFirewallRule -DisplayGroup "Remote Desktop"
   exit
   ```

18.Create an Admin User Account.

```cmd
net user /add itadmin Welcome1
net localgroup administrators itadmin /add
```

or

```Powershell
$Password = Read-Host -AsSecureString
New-LocalUser "itadmin" -Password $Password -FullName "itadmin" -Description "local admin account."
Add-LocalGroupMember -Group "Administrators" -Member "itadmin"
```

19.To Run Commands in current powershell instance without changing global execution policies use below snippet.

```Powershell
Set-ExecutionPolicy Bypass -Scope Process
```

20.Check list of local installed softwares

```Powershell
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize > C:\InstalledSoftwareList.txt
```

or

```Powershell
Get-CimInstance -ClassName win32_product
```

or

```powershell
Get-WmiObject -Class Win32_Product | Select-Object Name,Vendor,version,Caption
```

21.Checking Biggest files

```Powershell
gci -r|sort -descending -property length | select -first 10 name, @{Name="Gigabytes";Expression={[Math]::round($_.length / 1GB, 2)}}
```

22.Set Firewall interface settings [ Public,Private,Domain]

```Powershell
Set-NetConnectionProfile -NetworkCategory DomainAuthenticated
```

23.How to Fix Windows 11 SSD Problem Using PowerShell

```Powershell
Get-PhysicalDisk 
Get-PhysicalDisk | Set-PhysicalDisk -MediaType SSD
Get-PhysicalDisk 
```

24.Find out maximum Supported RAM on a machine where MaxCapacity is in KB and devided in total no of devices

```cmd
wmic memphysical get MaxCapacity, MemoryDevices

Result:-
MaxCapacity  MemoryDevices
67108864     2

```

25.Universal Powershell installation/Deployment script.

```Powershell
iex "& { $(irm https://aka.ms/install-powershell.ps1)} -usemsi -quiet"
```

26.Get-loggedin username

```Powershell
((Get-WMIObject -ClassName Win32_ComputerSystem).Username).Split('\')[1]
```

27. Script to excludes all bult-in or special profile folders

```powershell
Get-WmiObject -Class Win32_UserProfile | Where-Object {$_.Special -eq $false} | Select-Object LocalPath, LastUseTime
```

28. Discover computers Public ip

```Powershell
(Invoke-RestMethod ipinfo.io/json).ip
```

29. Get computer model

```Powershell
(Get-CimInstance Win32_ComputerSystem).model
```
30 get computer serial number

```Powershell
(Get-CimInstance Win32_Bios).serialnumber
```
31 get computer Biosversion

```Powershell
(Get-CimInstance Win32_Bios).smbbiosversion
```

## Active Directory one liners

Before running any ActiveDirectory commands we need to import Ad-Module.
> Import-Module ActiveDirectory

   1. Get All Members of a Group by name and ID

```Powershell
Get-ADGroupMember -Identity <group_name> -Recursive | select name,SamAccountName
```

2.Finding inactive users (no activity for 195 days or more)

```powershell
write-Host "Getting inactive User accounts the are enabled" n

$inacUser = Search-ADAccount -AccountInactive -TimeSpan $tspan -UsersOnly |Where-Object { $_.Enabled -eq $true } |select name,DistinguishedName,LastLogonDate

Write-host $inacuser.count -foreground Green “Number of inactive user accounts that are enabled”
```

3.Finding New Users created in last 7 days.

```Powershell
write-Host "Getting users created within a week." n

$ADuserInWeek = Get-ADUser -Filter {whenCreated -ge $week} -Properties Whencreated | select Name,whenCreated,DistinguishedName

Write-Host $ADUserinweek.count -ForegroundColor Green “Number of users created in the last 7 days” `n
```

4.Find Domain Controllers on Your Domain.

```Powershell
Resolve-DnsName -Type ALL -Name _ldap._tcp.dc._msdcs.$env:userdnsdomain
```
```Powershell
get-ciminstance

5.List Software Available for Uninstall .

```Powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table
```

6.Install PowerShell Core (6 and 7).

```Powershell
Invoke-Expression "& { $(Invoke-RestMethod -Uri aka.ms/install-powers…) }" -UseMSI -Preview
```

7.**Get ADuser last logon information of all the users**

```Powershell
Get-ADUser -Filter {enabled -eq $true} -Properties LastLogonTimeStamp | Select-Object Name,@{Name="Stamp"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp).ToString('dd-MM-yyyy_hh:mm:ss')}}
```

8.Back up all production Group Policy Objects

```Powershell
Backup-GPO –All –Path C:\Temp\AllGPO
```

9. [Troubleshoot hybrid Azure Active Directory-joined devices](https://docs.microsoft.com/en-us/azure/active-directory/devices/troubleshoot-device-dsregcmd#:~:text=To%20run%20diagnostics%20in%20SYSTEM,in%20the%20pre%2Dcheck%20phase.)

```cmd
dsregcmd /status
```

10.Discovering AD-Roles and their corresponding servers.

```
Get-Adforest ad.wipro.com | Forest-table Schemamaster,domainnamingmaster
```

## 11. List Current FSMO Role Holders  

   a ). Get domain level FSMO roles

   ```Powershell
   get-addomain | select InfrastructureMaster, PDCEmulator, RIDMaster
   ```

   b ). Get forest level FSMO roles

   ```Powershell
   Get-ADForest | select DomainNamingMaster, SchemaMaster
   ```

## 12. Transfer FSMO Roles

   1. Transfer PDCEmulator

   ```Powershell
   Move-ADDirectoryServerOperationMasterRole -Identity "dc1" PDCEmulator
   ```

   2. Transfer RIDMaster

   ```Powershell
   Move-ADDirectoryServerOperationMasterRole -Identity "dc1" RIDMaster
   ```

   3. Transfer InfrastrctureMaster

   ```Powershell
   Move-ADDirectoryServerOperationMasterRole -Identity "dc1" Infrastructuremaster
   ```

   4. Transfer DomainNamingMaster

   ```Powershell
   Move-ADDirectoryServerOperationMasterRole -Identity "dc1" DomainNamingmaster
   ```

   5. Transfer SchemaMaster

   ```Powershell
   Move-ADDirectoryServerOperationMasterRole -Identity "dc1" SchemaMaster
   ```
## 13. Join a PC to Domain

```Powershell
Add-computer -DomainName contoso.com -Credential contoso.com\Admin -verbose -Restart -force
```