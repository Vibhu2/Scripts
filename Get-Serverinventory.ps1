function Get-ServerInventory
{
    [CmdletBinding()]
    param (
        [string]$ComputerName = $env:COMPUTERNAME,
        [switch]$ExportCSV,
        [string]$OutputPath = "$env:USERPROFILE\Desktop\ServerInventory-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
        [switch]$SkipStore,
        [switch]$IncludeAD
    )

    # Create output directory if exporting
    if ($ExportCSV -and !(Test-Path -Path $OutputPath))
    {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # Function to get system information
    function Get-SystemInformation
    {
        param ([string]$ComputerName = $env:COMPUTERNAME)
        try
        {
            if ($ComputerName -eq $env:COMPUTERNAME)
            {
                $computerInfo = Get-ComputerInfo
                $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' -and $_.InterfaceAlias -notmatch 'vEthernet' } | Select-Object -First 1).IPAddress
            }
            else
            {
                $computerInfo = Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-ComputerInfo }
                $ipAddress = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' -and $_.InterfaceAlias -notmatch 'vEthernet' } | Select-Object -First 1).IPAddress
                }
            }
            $systemInfo = [PSCustomObject]@{
                 # Basic Computer Identification
                'Computer Name'              = $ComputerName
                'DNS Hostname'               = $computerInfo.CsDNSHostname
                'Primary IP'                 = $ipAddress
                
                # Operating System Detail
                'OS Name'                    = $computerInfo.OSName
                'OS Version'                 = $computerInfo.OSVersion
                'OS Build'                   = $computerInfo.OSBuildNumber
                'OS Display Version'         = $computerInfo.OSDisplayVersion
                'OS Install Date'            = $computerInfo.OsInstallDate
                'Windows Version'            = $computerInfo.WindowsVersion
                'Hardware Abstraction Layer' = $computerInfo.OsHardwareAbstractionLayer
                
                # BIOS and Manufacturer Details
                'BIOS Version'               = $computerInfo.BiosSMBIOSBIOSVersion
                'BIOS Manufacturer'          = $computerInfo.BiosManufacturer
                'System Manufacturer'        = $computerInfo.CsManufacturer
                'System Model'               = $computerInfo.CsModel
                'BISO Type'                  = $computerInfo.BiosfirmwareType

                # Domain and Network Details
                'Domain'                     = $computerInfo.CsDomain
                'Domain Role'                = $computerInfo.CsDomainRole

                # Processor and Memory Details
                'Processor'                  = $computerInfo.CsProcessors.Name
                'Cores'                      = $computerInfo.CsProcessors.NumberOfCores
                'Logical Processors'         = $computerInfo.CsProcessors.NumberOfLogicalProcessors
                'Total Memory (GB)'          = [math]::Round($computerInfo.OsTotalVisibleMemorySize / 1MB, 2)
                'Free Memory (GB)'           = [math]::Round($computerInfo.OsFreePhysicalMemory / 1MB, 2)
                'OSServerLevel'              = $computerInfo.OSServerLevel
                'Logon Server'               = $computerInfo.LogonServer
                'Time Zone'                  = $computerInfo.TimeZone
                'Last boot time'             = $computerInfo.osLastBootUpTime
            }
            return $systemInfo
        }
        catch
        {
            Write-Warning "Error collecting system information: $_"
            return $null
        }
    }

    # Function to get disk information
    function Get-DiskInformation
    {
        param ([string]$ComputerName)
        try
        {
            $params = @{
                Class  = 'Win32_LogicalDisk'
                Filter = "DriveType=3"
            }
            if ($ComputerName -ne $env:COMPUTERNAME)
            {
                $params['ComputerName'] = $ComputerName
            }
            $disks = Get-WmiObject @params
            $formattedDisks = $disks | Select-Object DeviceID, 
            @{Name = "Size (GB)"; Expression = { [math]::Round($_.Size / 1GB, 2) } }, 
            @{Name = "Used Space (GB)"; Expression = { [math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2) } }, 
            @{Name = "Free Space (GB)"; Expression = { [math]::Round($_.FreeSpace / 1GB, 2) } },
            @{Name = "Free (%)"; Expression = { [math]::Round(($_.FreeSpace / $_.Size) * 100, 2) } }
            return $formattedDisks
        }
        catch
        {
            Write-Warning "Error collecting disk information: $_"
            return $null
        }
    }

    # Function to get network information
    function Get-NetworkInformation
    {
        param ([string]$ComputerName)
        try
        {
            $scriptBlock = {
                Get-NetAdapter | Where-Object Status -eq "Up" | 
                    ForEach-Object {
                        $config = Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4
                        [PSCustomObject]@{
                            'Name'                  = $_.Name
                            'Interface Description' = $_.InterfaceDescription
                            'MAC Address'           = $_.MacAddress
                            'IPv4 Address'          = $config.IPAddress
                            'Subnet Mask'           = $config.PrefixLength
                            'Speed (Mbps)'          = $_.LinkSpeed
                        }
                    }
            }
            if ($ComputerName -eq $env:COMPUTERNAME)
            {
                $netAdapters = & $scriptBlock
            }
            else
            {
                $netAdapters = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock
            }
            return $netAdapters
        }
        catch
        {
            Write-Warning "Error collecting network information: $_"
            return $null
        }
    }

    # Function to get share information
    function Get-ShareInformation
    {
        param ([string]$ComputerName)
        try
        {
            $scriptBlock = {
                $shares = Get-SmbShare | Where-Object { $_.ShareType -eq 'FileSystemDirectory' -and $_.Name -notlike '*$' }
                if ($shares)
                {
                    $shares | Select-Object Name, Path, Description, ShareState, FolderEnumerationMode, ConcurrentUserLimit
                }
                else
                {
                    Write-Output "No shares found"
                }
            }
            if ($ComputerName -eq $env:COMPUTERNAME)
            {
                $formattedShares = & $scriptBlock
            }
            else
            {
                $formattedShares = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock
            }
            return $formattedShares
        }
        catch
        {
            Write-Warning "Error collecting share information: $_"
            return $null
        }
    }

    # Function to get printer information
    function Get-PrinterInformation
    {
        param ([string]$ComputerName)
        try
        {
            $scriptBlock = {
                $printers = Get-Printer | Select-Object Name, DriverName, PortName, Published, Shared, ShareName, Type, DeviceType
                $drivers = Get-PrinterDriver | Select-Object Name, Manufacturer, InfPath
                $combined = $printers | ForEach-Object {
                    $printer = $_
                    $driver = $drivers | Where-Object { $_.Name -eq $printer.DriverName }
                    [PSCustomObject]@{
                        PrinterName  = $printer.Name
                        DriverName   = $printer.DriverName
                        PortName     = $printer.PortName
                        Published    = $printer.Published
                        Shared       = $printer.Shared
                        ShareName    = $printer.ShareName
                        Type         = $printer.Type
                        DeviceType   = $printer.DeviceType
                        Manufacturer = $driver.Manufacturer
                        InfPath      = $driver.InfPath
                    }
                }
                $combined
            }
            if ($ComputerName -eq $env:COMPUTERNAME)
            {
                $printerInfo = & $scriptBlock
            }
            else
            {
                $printerInfo = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock
            }
            return $printerInfo
        }
        catch
        {
            Write-Warning "Error collecting printer information: $_"
            return $null
        }
    }

    # Function to get Windows updates
    function Get-WindowsUpdateInfo
    {
        param ([string]$ComputerName)
        try
        {
            $params = @{}
            if ($ComputerName -ne $env:COMPUTERNAME)
            {
                $params['ComputerName'] = $ComputerName
            }
            $updates = Get-HotFix @params | Select-Object Description, HotFixID, InstalledOn | Sort-Object InstalledOn -Descending
            return $updates
        }
        catch
        {
            Write-Warning "Error collecting Windows updates: $_"
            return $null
        }
    }

    # Function to get Windows features
    function Get-WindowsFeaturesInfo
    {
        param ([string]$ComputerName)
        try
        {
            $scriptBlock = {
                Get-WindowsFeature | Where-Object { $_.InstallState -eq "Installed" } | 
                    Select-Object Name, DisplayName, InstallState, FeatureType
            }
            if ($ComputerName -eq $env:COMPUTERNAME)
            {
                $features = & $scriptBlock
            }
            else
            {
                $features = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock
            }
            $roles = $features | Where-Object { $_.FeatureType -eq "Role" }
            $roleServices = $features | Where-Object { $_.FeatureType -eq "Role Service" }
            $otherFeatures = $features | Where-Object { $_.FeatureType -eq "Feature" }
            return @{
                Roles        = $roles
                RoleServices = $roleServices
                Features     = $otherFeatures
                AllFeatures  = $features
            }
        }
        catch
        {
            Write-Warning "Error collecting Windows features: $_"
            return $null
        }
    }

    # Function to get installed applications
    function Get-InstalledApplications
    {
        param ([string]$ComputerName)
        try
        {
            $scriptBlock = {
                Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, 
                HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | 
                    Where-Object { $_.DisplayName -ne $null } |
                    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName
            }
            if ($ComputerName -eq $env:COMPUTERNAME)
            {
                $formattedApps = & $scriptBlock
            }
            else
            {
                $formattedApps = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock
            }
            return $formattedApps
        }
        catch
        {
            Write-Warning "Error collecting installed applications: $_"
            return $null
        }
    }

    # Function to get Windows Store apps
    function Get-WindowsStoreApps
    {
        param ([string]$ComputerName)
        try
        {
            $scriptBlock = {
                Get-AppxPackage | Select-Object Name, Version, Publisher, Architecture | Sort-Object Name
            }
            if ($ComputerName -eq $env:COMPUTERNAME)
            {
                $formattedStoreApps = & $scriptBlock
            }
            else
            {
                $formattedStoreApps = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock
            }
            return $formattedStoreApps
        }
        catch
        {
            Write-Warning "Error collecting Windows Store applications: $_"
            return $null
        }
    }

    # Function to get DHCP information
    function Get-DHCPInformation
    {
        param ([string]$ComputerName)
        try
        {
            $scopes = Get-DhcpServerv4Scope -ComputerName $ComputerName
            $serverOptions = Get-DhcpServerv4OptionValue -ComputerName $ComputerName
            if ($scopes)
            {
                $reservations = Get-DhcpServerv4Reservation -ComputerName $ComputerName -ScopeId $scopes.ScopeId
            }
            else
            {
                $reservations = $null
            }
            $ipv6Scopes = Get-DhcpServerv6Scope -ComputerName $ComputerName
            if ($ipv6Scopes)
            {
                $ipv6ServerOptions = Get-DhcpServerv6OptionValue -ComputerName $ComputerName
                $ipv6Reservations = Get-DhcpServerv6Reservation -ComputerName $ComputerName -ScopeId $ipv6Scopes.ScopeId
            }
            else
            {
                $ipv6ServerOptions = $null
                $ipv6Reservations = $null
            }
            $dhcpv4DnsSettings = Get-DhcpServerv4DnsSetting -ComputerName $ComputerName
            $dhcpv6DnsSettings = Get-DhcpServerv6DnsSetting -ComputerName $ComputerName
            return @{
                Scopes            = $scopes
                ServerOptions     = $serverOptions
                Reservations      = $reservations
                IPv6Scopes        = $ipv6Scopes
                IPv6ServerOptions = $ipv6ServerOptions
                IPv6Reservations  = $ipv6Reservations
                DHCPv4DnsSettings = $dhcpv4DnsSettings
                DHCPv6DnsSettings = $dhcpv6DnsSettings
            }
        }
        catch
        {
            Write-Warning "Error collecting DHCP information: $_"
            return $null
        }
    }

    # Function to get Active Directory information
    function Get-ActiveDirectoryInfo
    {
        param ([string]$ComputerName)
        try
        {
            if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue))
            {
                Import-Module ActiveDirectory -ErrorAction Stop
            }
            $domainControllers = Get-ADDomainController -Filter * | Select-Object Name, Domain, Forest, OperationMasterRoles, IsReadOnly
            $allServers = Get-ADComputer -Filter { OperatingSystem -Like "*Server*" } | Select-Object Name, DNSHostName, Enabled, OperatingSystem, OperatingSystemVersion
            $fsmoRoles = [PSCustomObject]@{
                InfrastructureMaster = (Get-ADDomain).InfrastructureMaster
                PDCEmulator          = (Get-ADDomain).PDCEmulator
                RIDMaster            = (Get-ADDomain).RIDMaster
                DomainNamingMaster   = (Get-ADForest).DomainNamingMaster
                SchemaMaster         = (Get-ADForest).SchemaMaster
            }
            $domainFunctionalLevel = (Get-ADDomain).DomainMode
            $forestFunctionalLevel = (Get-ADForest).ForestMode
            $recycleBinEnabled = (Get-ADOptionalFeature -Filter { Name -eq 'Recycle Bin Feature' }).EnabledScopes.Count -gt 0
            $tombstoneLifetime = (Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -Properties tombstoneLifetime).tombstoneLifetime
            $users = Get-ADUser -Filter * -Properties SamAccountName, ProfilePath, ScriptPath, homeDrive, homeDirectory
            $userFolderReport = foreach ($user in $users)
            {
                [PSCustomObject]@{
                    SamAccountName = $user.SamAccountName
                    ProfilePath    = if ([string]::IsNullOrEmpty($user.ProfilePath)) { "N/A" } else { $user.ProfilePath }
                    LogonScript    = if ([string]::IsNullOrEmpty($user.ScriptPath)) { "N/A" } else { $user.ScriptPath }
                    HomeDrive      = if ([string]::IsNullOrEmpty($user.homeDrive)) { "N/A" } else { $user.homeDrive }
                    HomeDirectory  = if ([string]::IsNullOrEmpty($user.homeDirectory)) { "N/A" } else { $user.homeDirectory }
                }
            }
            $totalUsers = $users.Count
            $scriptBlock = {
                if (Test-Path -Path "C:\Windows\SYSVOL\sysvol")
                {
                    Get-ChildItem -Recurse -Path "C:\Windows\SYSVOL\sysvol" -ErrorAction SilentlyContinue | 
                        Where-Object { $_.Extension -in ".bat", ".cmd", ".ps1", ".vbs" } | 
                        Select-Object FullName, Length, LastWriteTime
                }
                else
                {
                    Write-Output "SYSVOL path not found"
                }
            }
            if ($ComputerName -eq $env:COMPUTERNAME)
            {
                $sysvolScripts = & $scriptBlock
            }
            else
            {
                $sysvolScripts = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock
            }
            $PUsers = @()
            try
            {
                $Members = Get-ADGroupMember -Identity 'Enterprise Admins' -Recursive -ErrorAction SilentlyContinue | Sort-Object Name
                $PUsers += foreach ($Member in $Members)
                {
                    Get-ADUser -Identity $Member.SID -Properties * | Select-Object Name, @{Name = 'Group'; expression = { 'Enterprise Admins' } }, WhenCreated, LastLogonDate, SamAccountName
                }
            }
            catch
            {
                Write-Warning "Enterprise Admins group not found or cannot be accessed"
            }
            try
            {
                $Members = Get-ADGroupMember -Identity 'Domain Admins' -Recursive | Sort-Object Name
                $PUsers += foreach ($Member in $Members)
                {
                    Get-ADUser -Identity $Member.SID -Properties * | Select-Object Name, @{Name = 'Group'; expression = { 'Domain Admins' } }, WhenCreated, LastLogonDate, SamAccountName
                }
            }
            catch
            {
                Write-Warning "Domain Admins group not found or cannot be accessed"
            }
            try
            {
                $Members = Get-ADGroupMember -Identity 'Schema Admins' -Recursive -ErrorAction SilentlyContinue | Sort-Object Name
                $PUsers += foreach ($Member in $Members)
                {
                    Get-ADUser -Identity $Member.SID -Properties * | Select-Object Name, @{Name = 'Group'; expression = { 'Schema Admins' } }, WhenCreated, LastLogonDate, SamAccountName
                }
            }
            catch
            {
                Write-Warning "Schema Admins group not found or cannot be accessed"
            }
            return @{
                DomainControllers     = $domainControllers
                AllServers            = $allServers
                FSMORoles             = $fsmoRoles
                UserFolderReport      = $userFolderReport
                SysvolScripts         = $sysvolScripts
                PrivilegedUsers       = $PUsers
                DomainFunctionalLevel = $domainFunctionalLevel
                ForestFunctionalLevel = $forestFunctionalLevel
                RecycleBinEnabled     = $recycleBinEnabled
                TombstoneLifetime     = $tombstoneLifetime
            }
        }
        catch
        {
            Write-Warning "Error collecting Active Directory information: $_"
            return $null
        }
    }

    # Function to get DNS information
    function Get-DNSInformation
    {
        param ([string]$ComputerName)
        try
        {
            $dnsServer = Get-DnsServer -ComputerName $ComputerName
            $dnsSettings = Get-DnsServerSetting -ComputerName $ComputerName
            $dnsForwarders = Get-DnsServerForwarder -ComputerName $ComputerName
            return @{
                DNSServer     = $dnsServer
                DNSSettings   = $dnsSettings
                DNSForwarders = $dnsForwarders
            }
        }
        catch
        {
            Write-Warning "Error collecting DNS information: $_"
            return $null
        }
    }

    # Simple section header
    function Write-SectionHeader
    {
        param ([string]$Title)
        Write-Host "`n----- $Title -----" -ForegroundColor Cyan
    }

    # COLLECTION AND OUTPUT SECTION
    Write-SectionHeader "SYSTEM INFORMATION"
    $systemInfo = Get-SystemInformation -ComputerName $ComputerName
    $systemInfo | Format-List
    if ($ExportCSV) { $systemInfo | Export-Csv -Path "$OutputPath\SystemInfo.csv" -NoTypeInformation }

    Write-SectionHeader "DISK INFORMATION"
    $diskInfo = Get-DiskInformation -ComputerName $ComputerName
    $diskInfo | Format-Table -AutoSize
    if ($ExportCSV) { $diskInfo | Export-Csv -Path "$OutputPath\DiskInfo.csv" -NoTypeInformation }

    Write-SectionHeader "NETWORK CONFIGURATION"
    $networkInfo = Get-NetworkInformation -ComputerName $ComputerName
    $networkInfo | Format-Table -AutoSize
    if ($ExportCSV) { $networkInfo | Export-Csv -Path "$OutputPath\NetworkInfo.csv" -NoTypeInformation }

    Write-SectionHeader "INSTALLED WINDOWS FEATURES AND ROLES"
    $featuresInfo = Get-WindowsFeaturesInfo -ComputerName $ComputerName
    Write-Host "INSTALLED ROLES:" -ForegroundColor Yellow
    $featuresInfo.Roles | Format-Table -AutoSize
    Write-Host "INSTALLED ROLE SERVICES:" -ForegroundColor Yellow
    $featuresInfo.RoleServices | Format-Table -AutoSize
    Write-Host "INSTALLED FEATURES:" -ForegroundColor Yellow
    $featuresInfo.Features | Format-Table -AutoSize
    if ($ExportCSV)
    { 
        $featuresInfo.AllFeatures | Export-Csv -Path "$OutputPath\WindowsFeatures.csv" -NoTypeInformation
        $featuresInfo.Roles | Export-Csv -Path "$OutputPath\WindowsRoles.csv" -NoTypeInformation
    }

    if ($featuresInfo.Roles.Name -contains "DHCP")
    {
        Write-SectionHeader "DHCP INFORMATION"
        $dhcpInfo = Get-DHCPInformation -ComputerName $ComputerName
        if ($dhcpInfo)
        {
            Write-Host "DHCPv4 SCOPES:" -ForegroundColor Yellow
            $dhcpInfo.Scopes | Format-Table -AutoSize
            Write-Host "DHCPv4 SERVER-LEVEL OPTIONS:" -ForegroundColor Yellow
            $dhcpInfo.ServerOptions | Format-Table -AutoSize
            Write-Host "DHCPv4 RESERVATIONS:" -ForegroundColor Yellow
            $dhcpInfo.Reservations | Format-Table -AutoSize
            Write-Host "DHCPv4 DNS SETTINGS:" -ForegroundColor Yellow
            $dhcpInfo.DHCPv4DnsSettings | Format-List
            if ($dhcpInfo.IPv6Scopes)
            {
                Write-Host "DHCPv6 SCOPES:" -ForegroundColor Yellow
                $dhcpInfo.IPv6Scopes | Format-Table -AutoSize
                Write-Host "DHCPv6 SERVER-LEVEL OPTIONS:" -ForegroundColor Yellow
                $dhcpInfo.IPv6ServerOptions | Format-Table -AutoSize
                Write-Host "DHCPv6 RESERVATIONS:" -ForegroundColor Yellow
                $dhcpInfo.IPv6Reservations | Format-Table -AutoSize
                Write-Host "DHCPv6 DNS SETTINGS:" -ForegroundColor Yellow
                $dhcpInfo.DHCPv6DnsSettings | Format-List
            }
            if ($ExportCSV)
            {
                $dhcpInfo.Scopes | Export-Csv -Path "$OutputPath\DHCPv4_Scopes.csv" -NoTypeInformation
                $dhcpInfo.ServerOptions | Export-Csv -Path "$OutputPath\DHCPv4_ServerOptions.csv" -NoTypeInformation
                $dhcpInfo.Reservations | Export-Csv -Path "$OutputPath\DHCPv4_Reservations.csv" -NoTypeInformation
                $dhcpInfo.DHCPv4DnsSettings | Export-Csv -Path "$OutputPath\DHCPv4_DnsSettings.csv" -NoTypeInformation
                if ($dhcpInfo.IPv6Scopes)
                {
                    $dhcpInfo.IPv6Scopes | Export-Csv -Path "$OutputPath\DHCPv6_Scopes.csv" -NoTypeInformation
                    $dhcpInfo.IPv6ServerOptions | Export-Csv -Path "$OutputPath\DHCPv6_ServerOptions.csv" -NoTypeInformation
                    $dhcpInfo.IPv6Reservations | Export-Csv -Path "$OutputPath\DHCPv6_Reservations.csv" -NoTypeInformation
                    $dhcpInfo.DHCPv6DnsSettings | Export-Csv -Path "$OutputPath\DHCPv6_DnsSettings.csv" -NoTypeInformation
                }
            }
        }
        else
        {
            Write-Host "No DHCP information available" -ForegroundColor Yellow
        }
    }

    if ($featuresInfo.Roles.Name -contains "DNS")
    {
        Write-SectionHeader "DNS SERVER INFORMATION"
        $dnsInfo = Get-DNSInformation -ComputerName $ComputerName
        if ($dnsInfo)
        {
            Write-Host "DNS SERVER DETAILS:" -ForegroundColor Yellow
            $dnsInfo.DNSServer | Format-List
            Write-Host "DNS SERVER SETTINGS:" -ForegroundColor Yellow
            $dnsInfo.DNSSettings | Format-List
            Write-Host "DNS FORWARDERS:" -ForegroundColor Yellow
            $dnsInfo.DNSForwarders | Format-Table -AutoSize
        }
        else
        {
            Write-Host "No DNS information available" -ForegroundColor Yellow
        }
    }

    Write-SectionHeader "INSTALLED APPLICATIONS"
    $appInfo = Get-InstalledApplications -ComputerName $ComputerName
    $appInfo | Format-Table -AutoSize
    if ($ExportCSV) { $appInfo | Export-Csv -Path "$OutputPath\InstalledApplications.csv" -NoTypeInformation }

    if (-not $SkipStore)
    {
        Write-SectionHeader "MODERN WINDOWS APPLICATIONS (STORE/UWP APPS)"
        $storeApps = Get-WindowsStoreApps -ComputerName $ComputerName
        $storeApps | Format-Table -AutoSize
        if ($ExportCSV) { $storeApps | Export-Csv -Path "$OutputPath\WindowsStoreApps.csv" -NoTypeInformation }
    }

    Write-SectionHeader "INSTALLED WINDOWS UPDATES"
    $updateInfo = Get-WindowsUpdateInfo -ComputerName $ComputerName
    $updateInfo | Format-Table -AutoSize
    if ($ExportCSV) { $updateInfo | Export-Csv -Path "$OutputPath\WindowsUpdates.csv" -NoTypeInformation }

    Write-SectionHeader "FILE SHARES"
    $shareInfo = Get-ShareInformation -ComputerName $ComputerName
    if ($shareInfo.Count -gt 0)
    {
        $shareInfo | Format-Table -AutoSize
        if ($ExportCSV) { $shareInfo | Export-Csv -Path "$OutputPath\ShareInfo.csv" -NoTypeInformation }
    }
    else
    {
        Write-Host "No shares found" -ForegroundColor Yellow
    }

    Write-SectionHeader "PRINTER INFORMATION"
    $printerInfo = Get-PrinterInformation -ComputerName $ComputerName
    if ($printerInfo.Count -gt 0)
    {
        $printerInfo | Format-Table -AutoSize
        if ($ExportCSV) { $printerInfo | Export-Csv -Path "$OutputPath\PrinterInfo.csv" -NoTypeInformation }
    }
    else
    {
        Write-Host "No printers found" -ForegroundColor Yellow
    }

    if ($IncludeAD)
    {
        Write-SectionHeader "ACTIVE DIRECTORY INFORMATION"
        $isDomainController = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
        if ($isDomainController)
        {
            $adInfo = Get-ActiveDirectoryInfo -ComputerName $ComputerName
            if ($adInfo)
            {
                Write-Host "DOMAIN CONTROLLERS:" -ForegroundColor Yellow
                $adInfo.DomainControllers | Format-Table -AutoSize
                Write-Host "FSMO ROLES:" -ForegroundColor Yellow
                $adInfo.FSMORoles | Format-List
                Write-Host "SERVERS IN DOMAIN:" -ForegroundColor Yellow
                $adInfo.AllServers | Format-Table -AutoSize
                Write-Host "USER FOLDERS INFORMATION:" -ForegroundColor Yellow
                $adInfo.UserFolderReport | Format-Table -AutoSize
                Write-Host "LOGON SCRIPTS IN SYSVOL:" -ForegroundColor Yellow
                $adInfo.SysvolScripts | Format-Table -AutoSize
                Write-Host "PRIVILEGED USERS:" -ForegroundColor Yellow
                $adInfo.PrivilegedUsers | Format-Table -AutoSize
                Write-Host "Domain Functional Level: $($adInfo.DomainFunctionalLevel)" -ForegroundColor Cyan
                Write-Host "Forest Functional Level: $($adInfo.ForestFunctionalLevel)" -ForegroundColor Cyan
                if ($adInfo.RecycleBinEnabled)
                {
                    Write-Host "Recycle Bin is ENABLED" -ForegroundColor Green
                }
                else
                {
                    Write-Host "Recycle Bin is NOT enabled" -ForegroundColor Red
                }
                Write-Host "Tombstone Lifetime: $($adInfo.TombstoneLifetime) days" -ForegroundColor Cyan
                if ($ExportCSV)
                {
                    $adInfo.DomainControllers | Export-Csv -Path "$OutputPath\DomainControllers.csv" -NoTypeInformation
                    $adInfo.AllServers | Export-Csv -Path "$OutputPath\DomainServers.csv" -NoTypeInformation
                    $adInfo.FSMORoles | Export-Csv -Path "$OutputPath\FSMORoles.csv" -NoTypeInformation
                    $adInfo.UserFolderReport | Export-Csv -Path "$OutputPath\UserFolderReport.csv" -NoTypeInformation
                    $adInfo.SysvolScripts | Export-Csv -Path "$OutputPath\SysvolScripts.csv" -NoTypeInformation
                    $adInfo.PrivilegedUsers | Export-Csv -Path "$OutputPath\PrivilegedUsers.csv" -NoTypeInformation
                }
            }
            else
            {
                Write-Host "Active Directory information could not be collected" -ForegroundColor Red
            }
        }
        else
        {
            Write-Host "This computer is not a domain controller. AD information collection skipped." -ForegroundColor Yellow
        }
    }

    if ($ExportCSV)
    {
        Write-Host "`nInventory data exported to: $OutputPath" -ForegroundColor Green
    }
}

Clear-Host
New-Item -Path 'C:\Realtime\' -ItemType Directory -Force
$sharepath = 'C:\Realtime\'
$username = $env:USERNAME
$hostname = hostname
$version = $PSVersionTable.PSVersion.ToString()
$datetime = Get-Date -Format "dd-MMM-yyyy-hh-mm-tt"
$filename = "${hostname}-${username}-${version}-${datetime}-Evaluation.txt"
$Transcript = Join-Path -Path $sharepath -ChildPath $filename
Write-Host "Transcript will be saved to: $Transcript"
Start-Transcript -Path $Transcript
Get-ServerInventory -IncludeAD
Stop-Transcript