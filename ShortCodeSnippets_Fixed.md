
# My collection of Powershell Snippets

1. **To get last boot time of the machine**.

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

2. **To get list of stopped services**.

```powershell
   Get-Service | Where-Object {$_.Status -eq "Stopped" -and $_.Starttype -eq "Automatic"}
```

3. **Setting execution Policy on machine**.

```powershell
   Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```

4. **Find Drive space**.

```powershell
   Get-PSDrive -PSProvider FileSystem
```

5. **Get Free Space for System Drive**.

```powershell
   (Get-PSDrive $Env:SystemDrive.Trim(':')).Free/1GB
```

6. **Check BIOS information**.

```powershell
   (Get-CimInstance Win32_BIOS)
```

7. **Check computer information**

```powershell
   Get-CimInstance Win32_ComputerSystem
```

8. **Check printer information on a machine**.

```powershell
   Get-CimInstance Win32_Printer | Select-Object Name, PortName, Default | Format-List
```

9. **Keep System Awake (VB Script)**.

```vbs
 set wsc = CreateObject("WScript.Shell")
 Do
     'Five minutes
     WScript.Sleep(5*60*1000)
     wsc.SendKeys("{F13}")
 Loop
```

10. **Install Powershell using Chocolatey**.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

choco install powershell -force --yes
choco install powershell-core -force --yes
Start-Sleep -Seconds 90
exit
exit
```

11. **Installing winget on a machine using command line**.

```powershell
invoke-webrequest
```

12. **Checking who rebooted a production server**.

```powershell
Get-EventLog –LogName System | Where-Object {$_.EventID –eq 1074} | Select-Object –Property TimeGenerated, UserName, Message
```

13. **Get AD user last logon information of all the users**.

```powershell
Get-ADUser -Filter {enabled -eq $true} -Properties LastLogonTimeStamp | Select-Object Name, @{Name="Stamp"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp).ToString('dd-MM-yyyy_hh:mm:ss')}}
```

14. **Back up all production Group Policy Objects**.

```powershell
Backup-GPO –All –Path C:\Temp\AllGPO
```

15. **Discovering AD-Roles and their corresponding servers**.

```powershell
Get-Adforest ad.wipro.com | Forest-table Schemamaster, domainnamingmaster
```

16. **List Current FSMO Role Holders** 
   a) Get domain level FSMO roles

   ```powershell
   get-addomain | select InfrastructureMaster, PDCEmulator, RIDMaster
   ```

   b) Get forest level FSMO roles

   ```powershell
   Get-ADForest | select DomainNamingMaster, SchemaMaster
   ```

## **Transfer FSMO Roles**

   1. **Transfer PDCEmulator**

   ```powershell
   Move-ADDirectoryServerOperationMasterRole -Identity "dc1" PDCEmulator
   ```

   2. **Transfer RIDMaster**

   ```powershell
   Move-ADDirectoryServerOperationMasterRole -Identity "dc1" RIDMaster
   ```

   3. **Transfer InfrastructureMaster**

   ```powershell
   Move-ADDirectoryServerOperationMasterRole -Identity "dc1" Infrastructuremaster
   ```

   4. **Transfer DomainNamingMaster**

   ```powershell
   Move-ADDirectoryServerOperationMasterRole -Identity "dc1" DomainNamingmaster
   ```

   5. **Transfer SchemaMaster**

   ```powershell
   Move-ADDirectoryServerOperationMasterRole -Identity "dc1" SchemaMaster
   ```

18. **Join a PC to Domain**

```powershell
Add-computer -DomainName contoso.com -Credential contoso.com\Admin -Verbose -Restart -Force
```
