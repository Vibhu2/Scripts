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
    #====================================================== Helper Functions ==================================================================
    #region Helper Functions
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
                'Computer Name'              = $env:COMPUTERNAME
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
        [CmdletBinding()]
        param (
            [string]$ComputerName = $env:COMPUTERNAME
        )

        Write-sectionheader "Network Configuration for $ComputerName"
    
        # Check if it's the local computer
        $isLocalComputer = ($ComputerName -eq $env:COMPUTERNAME) -or ($ComputerName -eq "localhost") -or ($ComputerName -eq ".")
    
        try
        {
            # Get all adapters information at once - use different approach for local vs remote
            if ($isLocalComputer)
            {
                $adapters = Get-NetIPConfiguration -ErrorAction Stop
                $allNetAdapters = Get-NetAdapter -ErrorAction Stop
                $allDnsServers = Get-DnsClientServerAddress -ErrorAction Stop
            }
            else
            {
                # For remote computers, use -ComputerName parameter when available
                $adapters = Get-NetIPConfiguration -ComputerName $ComputerName -ErrorAction Stop
            
                # Some cmdlets don't have -ComputerName parameter, fall back to direct query with filters
                $allNetAdapters = Get-WmiObject -Class Win32_NetworkAdapter -ComputerName $ComputerName -ErrorAction Stop
                $allNetAdapterConfigs = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $ComputerName -ErrorAction Stop
            }
        }
        catch
        {
            Write-Host "Failed to retrieve network configuration for $ComputerName" -ForegroundColor Red
            Write-Host "Error: $_" -ForegroundColor Red
            Write-Host "`nTroubleshooting tips:" -ForegroundColor Yellow
            Write-Host " - Ensure the remote computer is online and accessible" -ForegroundColor Yellow
            Write-Host " - Check if the necessary Windows firewall rules are enabled" -ForegroundColor Yellow
            return
        }

        foreach ($adapter in $adapters)
        {
            Write-Host "`n======================================" -ForegroundColor Cyan
            Write-Host "Adapter: $($adapter.InterfaceAlias)" -ForegroundColor Yellow
            Write-Host "--------------------------------------"
        
            if ($isLocalComputer)
            {
                # Use filtered collections instead of additional queries
                $netAdapter = $allNetAdapters | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex }
                $dns = $allDnsServers | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex }
            
                Write-Host " Description        : $($adapter.InterfaceDescription)"
                Write-Host " IPv4 Address       : $($adapter.IPv4Address.IPAddress)"
                Write-Host " IPv6 Address       : $($adapter.IPv6Address.IPAddress)"
                Write-Host " Subnet Prefix      : $($adapter.IPv4Address.PrefixLength)"
                Write-Host " Default Gateway    : $($adapter.IPv4DefaultGateway.NextHop)"
                Write-Host " DNS Servers        : $($dns.ServerAddresses -join ', ')"
                Write-Host " DHCP Enabled       : $($adapter.DhcpEnabled)"
                Write-Host " MAC Address        : $($netAdapter.MacAddress)"
                Write-Host " Interface Index    : $($adapter.InterfaceIndex)"
                Write-Host " Status             : $($netAdapter.Status)"
            }
            else
            {
                # For remote computers, use WMI data
                $netAdapter = $allNetAdapters | Where-Object { $_.DeviceID -eq $adapter.InterfaceIndex }
                $netAdapterConfig = $allNetAdapterConfigs | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex }
            
                Write-Host " Description        : $($adapter.InterfaceDescription)"
                Write-Host " IPv4 Address       : $($adapter.IPv4Address.IPAddress)"
                Write-Host " IPv6 Address       : $($adapter.IPv6Address.IPAddress)"
                Write-Host " Subnet Prefix      : $($adapter.IPv4Address.PrefixLength)"
                Write-Host " Default Gateway    : $($adapter.IPv4DefaultGateway.NextHop)"
                Write-Host " DNS Servers        : $($netAdapterConfig.DNSServerSearchOrder -join ', ')"
                Write-Host " DHCP Enabled       : $($netAdapterConfig.DHCPEnabled)"
                Write-Host " MAC Address        : $($netAdapterConfig.MACAddress)"
                Write-Host " Interface Index    : $($adapter.InterfaceIndex)"
                Write-Host " Status             : $($netAdapter.NetConnectionStatus)"
            }
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

    # Function to get Azure AD Join status
    function Get-AzureADJoinStatus
    {
        param ([string]$ComputerName = $env:COMPUTERNAME)
        try
        {
            # Grab whatever dsregcmd emits
            $scriptBlock = {
                $status = dsregcmd /status 2>&1
                
                if ($status)
                {
                    # Joined (or at least we got output)—return the full status
                    return $status
                }
                else
                {
                    # No output ⇒ not joined
                    return "Server is NOT Azure AD Joined."
                }
            }
            
            if ($ComputerName -eq $env:COMPUTERNAME)
            {
                return & $scriptBlock
            }
            else
            {
                return Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock
            }
        }
        catch
        {
            # Command itself failed ⇒ treat as not joined
            return "Server is NOT Azure AD Joined."
        }
    }
    
    # Helper function for Azure AD Join status (simplified version)
    function Get-AzureADJoinStatusSimple
    {
        param ([string]$ComputerName = $env:COMPUTERNAME)
        try
        {
            $scriptBlock = {
                if (dsregcmd /status 2>&1)
                { 
                    Write-Output '✅ Joined to Azure AD' 
                }
                else
                { 
                    Write-Output '❌ Not joined' 
                }
            }
            
            if ($ComputerName -eq $env:COMPUTERNAME)
            {
                return & $scriptBlock
            }
            else
            {
                return Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock
            }
        }
        catch
        {
            return "❌ Not joined"
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
            $allServers = Get-ADComputer -Filter { OperatingSystem -Like "Windows Server*" } -Property * | Select-Object Name, IPv4Address, OperatingSystem, OperatingSystemVersion, ENABLED, LastLogonDate, WhenCreated | Sort-Object OperatingSystemVersion 

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
                    $folderpath = (Get-ChildItem "C:\Windows\SYSVOL\sysvol" | Where-Object { $_.PSIsContainer } | Select-Object -First 1).FullName
                    Get-ChildItem -Recurse -Path "$folderpath" -ErrorAction SilentlyContinue | 
                        Where-Object { $_.Extension -in ".bat", ".cmd", ".ps1", ".vbs",".exe",".msi" } | 
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
            try
            {
                $forestFunctionalLevel = (Get-ADForest).ForestMode
                $domainFunctionalLevel = (Get-ADDomain).DomainMode
            }
            catch
            {
                Write-Warning "Can't detect functional levels"
            }
            # Check if AD recyclebin is enabled
            try
            {
                $RecyclebinStatus = if ((Get-ADOptionalFeature -Filter 'Name -eq "Recycle Bin Feature"').EnabledScopes) { "✅ ENABLED" } else { "❌ Recycle Bin is NOT enabled" }
            }
            catch
            {
                Write-Warning "Can't detect Recyclebin status"
            }
            
            # Get Azure AD Join Status using the function
            $AzureADJoinStatus = Get-AzureADJoinStatusSimple
                              
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
                DomainFunctLev        = $domainFunctionalLevel
                ForestFunLev          = $forestFunctionalLevel
                TotalADUsers          = $totalUsers
                ADRecyclebin          = $RecyclebinStatus
                AzureADJoinStatus     = $AzureADJoinStatus
            }
        }
        catch
        {
            Write-Warning "Error collecting Active Directory information: $_"
            return $null
        }
    }

    #function to get Group policy Information
    function Get-GPOInformation
    {
        [CmdletBinding()]
        param()
    
        # Ensure the GroupPolicy module is loaded
        if (-not (Get-Module -Name GroupPolicy -ListAvailable))
        {
            Import-Module GroupPolicy -ErrorAction Stop
        }
    
        # Retrieve all GPOs
        $gpos = Get-GPO -All
    
        # If no GPOs were found, error out
        if (-not $gpos)
        {
            Write-Error "No Group Policy Objects found in the domain."
            return
        }
        else
        {
            # Select and display all desired properties
            $gpos |
                Select-Object `
                    Id,
                DisplayName,
                GpoStatus,
                ModificationTime,
                CreationTime,
                Description |
                Sort-Object -Property ModificationTime |
                Format-Table -AutoSize
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

    # Function to Get User login information on Terminal server

    function Get-RDSUserInformation
    {
        param ([string]$ComputerName)
        try
        {
            $scriptBlock = {
                Get-RDUserSession | Select-Object UserName, SessionId, SessionState, HostServer, ClientName, ClientIP, LogonTime
            }
            if ($ComputerName -eq $env:COMPUTERNAME)
            {
                $userSessions = & $scriptBlock
            }
            else
            {
                $userSessions = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock
            }
            return $userSessions
        }
        catch
        {
            Write-Warning "Error collecting RDS user information: $_"
            return $null
        }
    }

    # Amazing section header ( Most important for consistent outputs)
    function Write-SectionHeader
    {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Title,
            [Parameter(Mandatory = $false)]
            [ConsoleColor]$BorderColor = [ConsoleColor]::Cyan,
            [Parameter(Mandatory = $false)]
            [ConsoleColor]$TextColor = [ConsoleColor]::White,
            [Parameter(Mandatory = $false)]
            [int]$Width = 80,
            [Parameter(Mandatory = $false)]
            [char]$BorderChar = '='
        )
    
        # Calculate padding for proper centering
        $padding = [Math]::Max(0, $Width - $Title.Length - 2)
        $leftPad = [Math]::Floor($padding / 2)
        $rightPad = $padding - $leftPad
        
        $borderLine = $BorderChar.ToString() * $Width
        $leftPadding = $BorderChar.ToString() * $leftPad
        $rightPadding = $BorderChar.ToString() * $rightPad
        
        # Create the complete middle line with title
        $titleLine = "$leftPadding $Title $rightPadding"
        
        # If the title line isn't exactly Width characters, adjust it
        if ($titleLine.Length -ne $Width)
        {
            # Fix the right padding to ensure exact width
            $rightPadding = $BorderChar.ToString() * ($rightPad + ($Width - $titleLine.Length))
            $titleLine = "$leftPadding $Title $rightPadding"
        }
        
        # Output with proper formatting
        Write-Host ""
        Write-Host $borderLine -ForegroundColor $BorderColor
        Write-Host $titleLine -ForegroundColor $BorderColor
        Write-Host $borderLine -ForegroundColor $BorderColor
        Write-Host ""
    }
    #endregion Helper Functions 

    #=================================================================== New Section ===================================================================
    function Get-InactiveUsers90Daysplus
    {
        Import-Module ActiveDirectory

        # Define the inactivity threshold (90 days ago)
        $daysInactive = 90
        $time = (Get-Date).AddDays(-$daysInactive)

        #Write-Output "Finding users inactive since $($time)...`n"

        # Get inactive users
        $inactiveUsers = Get-ADUser -Filter { enabled -eq $true -and lastLogonTimestamp -lt $time } -Properties lastLogonTimestamp |
            Select-Object Name, SamAccountName, @{Name = "LastLogonDate"; Expression = { [DateTime]::FromFileTime($_.lastLogonTimestamp) } }

        Write-Output "Inactive Users (90+ days):"
        Write-Output "Total Number of Inactive Computers: $($inactiveUsers.Count)"
        $inactiveUsers | Sort-Object -Property LastLogonDate
    }
    
    #_________________________________________________________________________________________________________________________________________

    function Get-InactiveComputers90Daysplus
    {
        # Set threshold to 90 days ago
        $daysInactive = 90
        $thresholdDate = (Get-Date).AddDays(-$daysInactive)

        Write-Output "Finding computers inactive for 90 days or more (since $($thresholdDate))...`n"

        # Get inactive computers
        $inactiveComputers = Get-ADComputer -Filter {
            Enabled -eq $true -and lastLogonTimestamp -lt $thresholdDate
        } -Properties lastLogonTimestamp, DNSHostName |
            Select-Object Name, DNSHostName,
            @{Name = "LastLogonDate"; Expression = { [DateTime]::FromFileTime($_.lastLogonTimestamp) } },
            @{Name = "IPAddress"; Expression = {
                    if ($_.DNSHostName)
                    {
                        try
                        {
                ($res = Resolve-DnsName $_.DNSHostName -ErrorAction Stop | Where-Object { $_.Type -eq "A" })[0].IPAddress
                        }
                        catch
                        {
                            "Unresolved"
                        }
                    }
                    else
                    {
                        "No DNSHostName"
                    }
                }
            }

        # Output to console
        Write-Output "Inactive Computers (90+ days):"
        Write-Output "Total Number of Inactive Computers: $($inactiveComputers.Count)"
        $inactiveComputers | Sort-Object -Property LastLogonDate
    }
    
    #_________________________________________________________________________________________________________________________________________
    function Get-AdAccountWithNoLogin
    {

        Import-Module ActiveDirectory

        Write-Output "`n--- Accounts With No Logon History ---`n"

        # Find users with no logon history
        $neverLoggedOnUsers = Get-ADUser -Filter { enabled -eq $true -and lastLogonTimestamp -notlike "*" } -Properties lastLogonTimestamp, whenCreated |
            Select-Object Name, SamAccountName, Enabled, whenCreated

        Write-Output "Users with no logon history:"
        $neverLoggedOnUsers | sort-object -property WhenCreated

        Write-Output "`nNumber of users with no logon history: $($neverLoggedOnUsers.Count)`n"


    }
    
    #_________________________________________________________________________________________________________________________________________

    Function Get-ExpiredUseraccounts
    {
        Import-Module ActiveDirectory

        # Get current date in FILETIME format
        $currentFileTime = [DateTime]::UtcNow.ToFileTime()

        Write-Output "`n--- Expired User Accounts ---`n"

        # Find expired user accounts (accountExpires not 0 or 9223372036854775807 and less than current time)
        $expiredUsers = Get-ADUser -Filter {
            accountExpires -lt $currentFileTime -and accountExpires -ne 0 -and accountExpires -ne 9223372036854775807
        } -Properties accountExpires, SamAccountName, Enabled |
            Select-Object Name, SamAccountName, Enabled, @{Name = "AccountExpires"; Expression = { [DateTime]::FromFileTime($_.accountExpires) } }

        # Output to console
        Write-Output "Expired user accounts:"
        $expiredUsers | Sort-object -property accountExpires

        Write-Output "`nNumber of expired user accounts: $($expiredUsers.Count)`n"

    }
    #_________________________________________________________________________________________________________________________________________
    Import-Module ActiveDirectory

    # Function 1: Users that don't require a password
    function Get-NoPasswordRequiredUsers
    {
        Write-Output "`n--- Users That Don't Require a Password ---`n"

        $users = Get-ADUser -Filter { PasswordNotRequired -eq $true -and Enabled -eq $true } -Properties PasswordNotRequired, whenCreated |
            Select-Object Name, SamAccountName, Enabled, whenCreated

        if ($users.Count -eq 0)
        {
            Write-Output "✅ No users found with 'PasswordNotRequired' enabled."
        }
        else
        {
            $users | Format-Table -AutoSize
            Write-Output "`nCount: $($users.Count)`n"
        }
    }

    #_________________________________________________________________________________________________________________________________________

    # Function 2: Users with password never expires + last logon info
    function Get-PasswordNeverExpiresUsers
    {
        Write-Output "`n--- Users With Passwords Set to Never Expire ---`n"

        $users = Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } -Properties PasswordNeverExpires, whenCreated, lastLogonTimestamp |
            Select-Object Name, SamAccountName, Enabled, whenCreated,
            @{Name = "LastLogon"; Expression = { if ($_.lastLogonTimestamp) { [DateTime]::FromFileTime($_.lastLogonTimestamp) } else { "Never Logged On" } } }

        # Sort by LastLogon (handles string and DateTime sorting by treating 'Never Logged On' as latest)
        $sortedUsers = $users | Sort-Object @{ Expression = { 
                if ($_.'LastLogon' -is [datetime]) { $_.'LastLogon' } else { [DateTime]::MaxValue } 
            }
        }

        $sortedUsers | Format-Table -AutoSize
        Write-Output "`nCount: $($sortedUsers.Count)`n"
    }

    #_________________________________________________________________________________________________________________________________________
    # Function 3: Admins with passwords older than 1 year
    function Get-OldAdminPasswords
    {
        Write-Output "`n--- Admins With Passwords Older Than 1 Year ---`n"

        $adminGroup = "Domain Admins"
        $threshold = (Get-Date).AddDays(-365)

        $admins = Get-ADGroupMember -Identity $adminGroup -Recursive | Where-Object { $_.objectClass -eq 'user' }

        $oldPasswordAdmins = foreach ($admin in $admins)
        {
            $user = Get-ADUser $admin.SamAccountName -Properties PasswordLastSet, Enabled
            if ($user.PasswordLastSet -lt $threshold)
            {
                [PSCustomObject]@{
                    Name            = $user.Name
                    SamAccountName  = $user.SamAccountName
                    Enabled         = $user.Enabled
                    PasswordLastSet = $user.PasswordLastSet
                }
            }
        }

        $oldPasswordAdmins | sort-object -property PasswordLastSet | Format-Table -AutoSize
        Write-Output "`nCount: $($oldPasswordAdmins.Count)`n"
    }
    

    #_________________________________________________________________________________________________________________________________________

    function Get-EmptyADGroups
    {
        Write-Output "`n--- Empty Active Directory Groups (Excluding All Default Groups) ---`n"

        # Exclude default groups
        $excludeGroups = @(
            "Domain Admins", "Domain Users", "Domain Guests", "Enterprise Admins", "Schema Admins",
            "Administrators", "Users", "Guests", "Account Operators", "Backup Operators",
            "Print Operators", "Server Operators", "Replicator", "DnsAdmins", "DnsUpdateProxy",
            "Cert Publishers", "Read-only Domain Controllers", "Group Policy Creator Owners",
            "Access Control Assistance Operators", "ADSyncBrowse", "ADSyncOperators", "ADSyncPasswordSet",
            "Allowed RODC Password Replication Group", "Certificate Service DCOM Access", "Cloneable Domain Controllers",
            "Cryptographic Operators", "DHCP Administrators", "DHCP Users", "Distributed COM Users", 
            "Enterprise Key Admins", "Enterprise Read-only Domain Controllers", "Event Log Readers", "Hyper-V Administrators",
            "Incoming Forest Trust Builders", "Key Admins", "Network Configuration Operators", "Office 365 Public Folder Administration",
            "Performance Log Users", "Performance Monitor Users", "Protected Users", "RAS and IAS Servers", 
            "RDS Endpoint Servers", "RDS Management Servers", "RDS Remote Access Servers", "Remote Management Users",
            "Storage Replica Administrators"
        )

        # Get all groups excluding the default ones
        $allGroups = Get-ADGroup -Filter * -Properties whenCreated, whenChanged |
            Where-Object { $excludeGroups -notcontains $_.Name }

        # Filter and check for empty groups
        $emptyGroups = foreach ($group in $allGroups)
        {
            $members = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction SilentlyContinue
            if (-not $members)
            {
                [PSCustomObject]@{
                    Name           = $group.Name
                    SamAccountName = $group.SamAccountName
                    Created        = $group.whenCreated
                    Modified       = $group.whenChanged
                }
            }
        }

        if ($emptyGroups.Count -eq 0)
        {
            Write-Output "✅ No empty non-default groups were found in Active Directory."
        }
        else
        {
            # Sort by Created date (ascending order)
            $emptyGroups | Sort-Object Created | Format-Table -AutoSize
            Write-Output "`nCount: $($emptyGroups.Count)`n"
        }
    }

    #_________________________________________________________________________________________________________________________________________
    function Get-ADGroupsWithMemberCount
    {
        Write-Output "`n--- Active Directory Groups with User Count (Sorted by Member Count) ---`n"

        # Exclude default groups
        $excludeGroups = @(
            "Domain Admins", "Domain Users", "Domain Guests", "Enterprise Admins", "Schema Admins",
            "Administrators", "Users", "Guests", "Account Operators", "Backup Operators",
            "Print Operators", "Server Operators", "Replicator", "DnsAdmins", "DnsUpdateProxy",
            "Cert Publishers", "Read-only Domain Controllers", "Group Policy Creator Owners",
            "Access Control Assistance Operators", "ADSyncBrowse", "ADSyncOperators", "ADSyncPasswordSet",
            "Allowed RODC Password Replication Group", "Certificate Service DCOM Access", "Cloneable Domain Controllers",
            "Cryptographic Operators", "DHCP Administrators", "DHCP Users", "Distributed COM Users", 
            "Enterprise Key Admins", "Enterprise Read-only Domain Controllers", "Event Log Readers", "Hyper-V Administrators",
            "Incoming Forest Trust Builders", "Key Admins", "Network Configuration Operators", "Office 365 Public Folder Administration",
            "Performance Log Users", "Performance Monitor Users", "Protected Users", "RAS and IAS Servers", 
            "RDS Endpoint Servers", "RDS Management Servers", "RDS Remote Access Servers", "Remote Management Users",
            "Storage Replica Administrators"
        )

        # Get all groups excluding the default ones
        $allGroups = Get-ADGroup -Filter * -Properties whenCreated, whenChanged |
            Where-Object { $excludeGroups -notcontains $_.Name }

        # Filter and check for groups, including empty and non-empty ones
        $groupDetails = foreach ($group in $allGroups)
        {
            $members = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction SilentlyContinue
            $memberCount = $members.Count
            [PSCustomObject]@{
                SamAccountName = $group.SamAccountName
                MemberCount    = $memberCount
                Created        = $group.whenCreated
                Modified       = $group.whenChanged
            }
        }

        if ($groupDetails.Count -eq 0)
        {
            Write-Output "✅ No groups were found in Active Directory."
        }
        else
        {
            # Sort by MemberCount (empty groups will appear on top) and display results
            $groupDetails | Sort-Object MemberCount, Created | Format-Table -AutoSize
            Write-Output "`nCount: $($groupDetails.Count)`n"
        }
    }


    #_________________________________________________________________________________________________________________________________________
    function Get-UnusedGPOs
    {
        Write-Output "`n--- Unused GPOs (Not Linked to Domain or OU) with Version Info ---`n"
    
        # Ensure GroupPolicy module is loaded
        Import-Module GroupPolicy -ErrorAction Stop

        $unusedGPOs = @()

        # Retrieve all GPOs
        $allGPOs = Get-GPO -All

        foreach ($gpo in $allGPOs)
        {
            # Generate XML report for this GPO
            $xmlReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml

            # Load into XML object
            [xml]$doc = $xmlReport

            # Count the <Link> nodes under GPO/LinksTo
            $linkCount = $doc.GPO.LinksTo.Link.Count

            if ($linkCount -eq 0)
            {
                $unusedGPOs += [PSCustomObject]@{
                    Name            = $gpo.DisplayName
                    UserVersion     = [int]$doc.GPO.UserVersion
                    ComputerVersion = [int]$doc.GPO.ComputerVersion
                    Created         = $gpo.CreationTime
                    Modified        = $gpo.ModificationTime
                    ID              = $gpo.Id
                }
            }
        }

        if ($unusedGPOs.Count -eq 0)
        {
            Write-Output "✅ No unused GPOs found."
        }
        else
        {
            # Sort by CreationTime and display, with ID last
            $unusedGPOs |
                Sort-Object Created |
                Format-Table Name, UserVersion, ComputerVersion, Created, Modified, ID -AutoSize

            Write-Output "`nTotal Unused GPOs: $($unusedGPOs.Count)`n"
        }
    }

    #_________________________________________________________________________________________________________________________________________

    function Get-GpoConnections
    {
        Import-Module ActiveDirectory
        Import-Module GroupPolicy

        $results = @()

        # Get all OUs
        $OUs = Get-ADOrganizationalUnit -Filter *

        foreach ($ou in $OUs)
        {
            $inheritance = Get-GPInheritance -Target $ou.DistinguishedName
            foreach ($link in $inheritance.GpoLinks)
            {
                # Extract only the OU name (e.g., from "OU=Staff,OU=BEBWS,DC=domain,DC=local" get "Staff")
                if ($ou.DistinguishedName -match '^OU=([^,]+)')
                {
                    $ouName = $matches[1]
                }
                else
                {
                    $ouName = $ou.DistinguishedName
                }

                $results += [PSCustomObject]@{
                    GPO       = $link.DisplayName
                    OU        = $ouName
                    Enforced  = $link.Enforced
                    LinkOrder = $link.Order
                }
            }
        }

        # Output only simplified fields
        $results | Select-Object GPO, OU, Enforced, LinkOrder | Format-Table -AutoSize
    }
   
    #_________________________________________________________________________________________________________________________________________
    function Get-GPOComprehensiveReport
    {
        param(
            [Parameter(Mandatory = $false)]
            [switch]$ShowAll
        )

        $gpos = Get-GPO -All

        foreach ($gpo in $gpos)
        {
            $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
            $xml = [xml]$report

            $links = @()

            foreach ($scope in $xml.GPO.LinksTo)
            {
                $linkObject = [pscustomobject]@{
                    GPOName      = $gpo.DisplayName
                    GPOID        = $gpo.Id
                    LinkScope    = $scope.SOMPath
                    LinkEnabled  = $scope.Enabled
                    Enforced     = $scope.NoOverride
                    GPOStatus    = $gpo.GpoStatus
                    CreatedTime  = $gpo.CreationTime
                    ModifiedTime = $gpo.ModificationTime
                }

                $links += $linkObject
            }

            if ($ShowAll -or $links.Count -gt 0)
            {
                $links
            }
        }
    }

    #_________________________________________________________________________________________________________________________________________

    function Get-FirewallPortRules
    {
        [CmdletBinding()]
        param (
            [Parameter(HelpMessage = "Include rules where Action = Block")]
            [switch]$IncludeBlocked,
        
            [Parameter(HelpMessage = "Include rules that are not enabled")]
            [switch]$IncludeDisabled,
        
            [Parameter(HelpMessage = "Filter by specific protocol (TCP, UDP, Any)")]
            [ValidateSet("TCP", "UDP", "Any", IgnoreCase = $true)]
            [string]$Protocol,
        
            [Parameter(HelpMessage = "Filter by specific port number")]
            [string]$Port,
        
            [Parameter(HelpMessage = "Show additional rule details including rule description")]
            [switch]$Detailed,
        
            [Parameter(HelpMessage = "Export results to CSV file")]
            [string]$ExportCSV,
        
            [Parameter(HelpMessage = "Include default Windows rules (otherwise only shows custom rules)")]
            [switch]$IncludeDefaultRules
        )

        # Display processing message
        $displayProtocol = if ($Protocol) { $Protocol } else { 'Any' }
        $displayPort = if ($Port) { $Port } else { 'Any' }

        Write-Verbose "Retrieving firewall rules with filters - Blocked: $IncludeBlocked, Disabled: $IncludeDisabled, Protocol: $displayProtocol, Port: $displayPort, Default Rules: $IncludeDefaultRules"

    
        # Get all matching firewall rules
        $rules = Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {
            $_.Direction -eq 'Inbound' -and
        ($IncludeBlocked -or $_.Action -eq 'Allow') -and
        ($IncludeDisabled -or $_.Enabled -eq $true) -and
            # Filter out default Windows rules unless specifically requested
        ($IncludeDefaultRules -or -not ($_.Owner -like "*Microsoft*" -or 
                $_.DisplayName -like "*Windows*" -or
                $_.DisplayGroup -like "*Windows*" -or
                $_.DisplayGroup -like "*Microsoft*" -or
                $_.Group -like "*Windows*" -or
                $_.Group -like "*Microsoft*" -or
                $_.Group -like "@*" -or
                $_.DisplayName -like "@*"))
        }
    
        Write-Verbose "Found $($rules.Count) matching base firewall rules"
    
        $results = [System.Collections.ArrayList]::new()
        $processedCount = 0
    
        foreach ($rule in $rules)
        {
            # Get associated port filters
            $portFilters = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
        
            # Skip rules without port filters unless we're viewing detailed info
            if (-not $portFilters -and -not $Detailed) { continue }
        
            # Get associated address filters for additional info
            $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
        
            # Get application filters for executable path
            $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
        
            # Get security filters for additional security info
            $securityFilter = Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
        
            $processedCount++
            Write-Progress -Activity "Processing Firewall Rules" -Status "Rule $processedCount of $($rules.Count)" -PercentComplete (($processedCount / $rules.Count) * 100)
        
            # If there are port filters, process each one
            if ($portFilters)
            {
                foreach ($filter in $portFilters)
                {
                    # Skip if protocol filter is specified and doesn't match
                    if ($Protocol -and $filter.Protocol -ne $Protocol) { continue }
                
                    # Skip if port filter is specified and doesn't match
                    if ($Port -and 
                   (-not $filter.LocalPort -or 
                    ($filter.LocalPort -ne $Port -and 
                        $filter.LocalPort -ne "Any" -and 
                        $filter.LocalPort -notlike "*,$Port,*" -and 
                        $filter.LocalPort -notlike "$Port,*" -and 
                        $filter.LocalPort -notlike "*,$Port"))) { continue }
                
                    # Create the output object with standard properties
                    $resultObj = [PSCustomObject]@{
                        RuleID      = $rule.Name
                        Name        = $rule.DisplayName
                        Enabled     = if ($rule.Enabled -eq $true) { "Yes" } else { "No" }
                        Direction   = $rule.Direction
                        Profile     = $rule.Profile
                        Action      = $rule.Action
                        Protocol    = if ($filter.Protocol -eq "Any") { "Any" } else { $filter.Protocol }
                        LocalPort   = if ($filter.LocalPort -eq "Any") { "Any" } else { $filter.LocalPort }
                        RemotePort  = if ($filter.RemotePort -eq "Any") { "Any" } else { $filter.RemotePort }
                        Program     = if ($appFilter.Program -eq "*") { "Any" } else { Split-Path $appFilter.Program -Leaf }
                        ProgramPath = if ($appFilter.Program -eq "*") { "Any" } else { $appFilter.Program }
                    }
                
                    # Add detailed properties if requested
                    if ($Detailed)
                    {
                        Add-Member -InputObject $resultObj -NotePropertyName "Description" -NotePropertyValue $rule.Description
                        Add-Member -InputObject $resultObj -NotePropertyName "Group" -NotePropertyValue $rule.Group
                        Add-Member -InputObject $resultObj -NotePropertyName "LocalAddress" -NotePropertyValue ($addressFilter.LocalAddress -join ", ")
                        Add-Member -InputObject $resultObj -NotePropertyName "RemoteAddress" -NotePropertyValue ($addressFilter.RemoteAddress -join ", ")
                        Add-Member -InputObject $resultObj -NotePropertyName "Authentication" -NotePropertyValue $securityFilter.Authentication
                        Add-Member -InputObject $resultObj -NotePropertyName "Encryption" -NotePropertyValue $securityFilter.Encryption
                    }
                
                    [void]$results.Add($resultObj)
                }
            }
            # If no port filters but detailed view requested, still include the rule
            elseif ($Detailed)
            {
                $resultObj = [PSCustomObject]@{
                    RuleID         = $rule.Name
                    Name           = $rule.DisplayName
                    Enabled        = if ($rule.Enabled -eq $true) { "Yes" } else { "No" }
                    Direction      = $rule.Direction
                    Profile        = $rule.Profile
                    Action         = $rule.Action
                    Protocol       = "N/A"
                    LocalPort      = "N/A"
                    RemotePort     = "N/A"
                    Program        = if ($appFilter.Program -eq "*") { "Any" } else { Split-Path $appFilter.Program -Leaf }
                    ProgramPath    = if ($appFilter.Program -eq "*") { "Any" } else { $appFilter.Program }
                    Description    = $rule.Description
                    Group          = $rule.Group
                    LocalAddress   = ($addressFilter.LocalAddress -join ", ")
                    RemoteAddress  = ($addressFilter.RemoteAddress -join ", ")
                    Authentication = $securityFilter.Authentication
                    Encryption     = $securityFilter.Encryption
                }
            
                [void]$results.Add($resultObj)
            }
        }
    
        Write-Progress -Activity "Processing Firewall Rules" -Completed
    
        # Export to CSV if requested
        if ($ExportCSV)
        {
            try
            {
                $results | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8
                Write-Host "Results exported to $ExportCSV" -ForegroundColor Green
            }
            catch
            {
                Write-Warning "Failed to export results to CSV: $_"
            }
        }
    
        # Output a summary before returning results
        Write-Host "`nFirewall Rules Summary:" -ForegroundColor Cyan
        Write-Host "------------------------" -ForegroundColor Cyan
        Write-Host "Total rules processed: $($rules.Count)" -ForegroundColor Cyan
        Write-Host "Rules with port filters: $($results.Count)" -ForegroundColor Cyan
        Write-Host "Enabled rules: $(($results | Where-Object { $_.Enabled -eq 'Yes' }).Count)" -ForegroundColor Cyan
        Write-Host "Blocked rules: $(($results | Where-Object { $_.Action -eq 'Block' }).Count)" -ForegroundColor Cyan
        if (-not $IncludeDefaultRules)
        {
            Write-Host "Rule type: Custom rules only (use -IncludeDefaultRules to see all)" -ForegroundColor Cyan
        }
        else
        {
            Write-Host "Rule type: All rules (including Windows defaults)" -ForegroundColor Cyan
        }
    
        if ($Protocol)
        {
            Write-Host "$Protocol protocol rules: $(($results | Where-Object { $_.Protocol -eq $Protocol }).Count)" -ForegroundColor Cyan
        }
    
        # Always sort results by Name before returning
        return $results | Sort-Object -Property Name
    }

    # Example usage:
    # Get all custom enabled "Allow" rules
    #Get-FirewallPortRules | Format-Table -AutoSize -Wrap

    # Get all custom rules including blocked and disabled
    # Get-FirewallPortRules -IncludeBlocked -IncludeDisabled | Format-Table -AutoSize -Wrap

    # Get all rules including default Windows rules
    # Get-FirewallPortRules -IncludeDefaultRules | Format-Table -AutoSize -Wrap

    # Filter by protocol and export to CSV
    # Get-FirewallPortRules -Protocol TCP -ExportCSV "C:\temp\firewall_tcp_rules.csv" | Format-Table -AutoSize

    # Get detailed information
    # Get-FirewallPortRules -Detailed -IncludeBlocked -IncludeDisabled | Format-Table -AutoSize -Wrap

    # Filter by specific port
    # Get-FirewallPortRules -Port 3389 | Format-Table -AutoSize
    #Get-FirewallPortRules -IncludeDefaultRules | FT -AutoSize

    #_____________________________________________________________________________________________________________________________________________________
    function Get-NonMicrosoftScheduledTasks
    {
        <#
    .SYNOPSIS
        Retrieves scheduled tasks that are not created by Microsoft or related to OneDrive.

    .DESCRIPTION
        Filters out scheduled tasks whose names or paths contain 'Microsoft' or 'OneDrive', 
        and excludes those authored by Microsoft. Returns details such as task name, state, 
        author, path, last run time, next run time, actions, and description.

    .OUTPUTS
        [PSCustomObject]

    .EXAMPLE
        Get-NonMicrosoftScheduledTasks
    #>

        Get-ScheduledTask | Where-Object {
        ($_.TaskName -notmatch 'Microsoft') -and
        ($_.TaskPath -notmatch 'Microsoft') -and
        ($_.TaskName -notmatch 'OneDrive')
        } | ForEach-Object {
            $definition = $_.Definition
            $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath

            if ($definition.Author -notmatch 'Microsoft')
            {
                [PSCustomObject]@{
                    TaskName    = $_.TaskName
                    State       = $_.State
                    Author      = $definition.Author
                    TaskPath    = $_.TaskPath
                    LastRunTime = $info.LastRunTime
                    NextRunTime = $info.NextRunTime
                    Actions     = ($definition.Actions | ForEach-Object { $_.Execute }) -join ', '
                    Description = $definition.Description
                }
            }
        }
    }

    #___________________________________________________________________________________________________________________________________________

    #=================================================================== New Section End ===============================================================
    #===================================================== Data Collection and Output: ========================================================
    
    function Write-SectionHeader
    {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Title,
            [Parameter(Mandatory = $false)]
            [ConsoleColor]$BorderColor = [ConsoleColor]::Cyan,
            [Parameter(Mandatory = $false)]
            [ConsoleColor]$TextColor = [ConsoleColor]::White,
            [Parameter(Mandatory = $false)]
            [int]$Width = 80,
            [Parameter(Mandatory = $false)]
            [char]$BorderChar = '=',
            [Parameter(Mandatory = $false)]
            [switch]$Markdown,
            [Parameter(Mandatory = $false)]
            [ValidateRange(1, 5)]
            [int]$HeaderLevel = 2,
            [Parameter(Mandatory = $false)]
            [switch]$NoBorder,
            [Parameter(Mandatory = $false)]
            [ValidateSet("None", "Asterisk", "Dash", "Underscore")]
            [string]$HorizontalRule = "None",
            [Parameter(Mandatory = $false)]
            [int]$HorizontalRuleLength = 30
        )

        if ($Markdown)
        {
            # Markdown format - using specified heading level (H1-H5)
            $headerMarker = "#" * $HeaderLevel
        
            # Output with proper markdown formatting
            Write-Output ""
            Write-Output "$headerMarker $Title"
        
            # Add horizontal rule if specified
            if ($HorizontalRule -ne "None")
            {
                Write-Output ""
                switch ($HorizontalRule)
                {
                    "Asterisk" { Write-Output ("*" * $HorizontalRuleLength) }
                    "Dash" { Write-Output ("-" * $HorizontalRuleLength) }
                    "Underscore" { Write-Output ("_" * $HorizontalRuleLength) }
                }
            }
            Write-Output ""
        }
        else
        {
            # Standard format for console and text files
            # Calculate padding for proper centering
            $padding = [Math]::Max(0, $Width - $Title.Length - 2)
            $leftPad = [Math]::Floor($padding / 2)
            $rightPad = $padding - $leftPad
        
            $borderLine = $BorderChar.ToString() * $Width
            $leftPadding = $BorderChar.ToString() * $leftPad
            $rightPadding = $BorderChar.ToString() * $rightPad
        
            # Create the complete middle line with title
            $titleLine = "$leftPadding $Title $rightPadding"
        
            # If the title line isn't exactly Width characters, adjust it
            if ($titleLine.Length -ne $Width)
            {
                # Fix the right padding to ensure exact width
                $rightPadding = $BorderChar.ToString() * ($rightPad + ($Width - $titleLine.Length))
                $titleLine = "$leftPadding $Title $rightPadding"
            }
        
            # For compatibility, use Write-Output instead of Write-Host when output needs to be captured
            if ($PSCmdlet.MyInvocation.PipelinePosition -lt $PSCmdlet.MyInvocation.PipelineLength)
            {
                # We're in a pipeline, so use Write-Output for redirection
                Write-Output ""
                if (-not $NoBorder) { Write-Output $borderLine }
                Write-Output $titleLine
                if (-not $NoBorder) { Write-Output $borderLine }
                Write-Output ""
            }
            else
            {
                # Direct console output with colors
                Write-Host ""
                if (-not $NoBorder) { Write-Host $borderLine -ForegroundColor $BorderColor }
                Write-Host $titleLine -ForegroundColor $TextColor
                if (-not $NoBorder) { Write-Host $borderLine -ForegroundColor $BorderColor }
                Write-Host ""
            }
        }
    }

    #===================================================== Data Collection and Output: ========================================================

    #region Data Collection and Output
    # COLLECTION AND OUTPUT SECTION

    # System Overview
    Write-SectionHeader -Title "SYSTEM OVERVIEW" -BorderColor Cyan -TextColor White -Width 80 -BorderChar '='

    Write-SectionHeader -Title "System Information" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
    $systemInfo = Get-SystemInformation -ComputerName $ComputerName
    $systemInfo | Format-List
    if ($ExportCSV) { $systemInfo | Export-Csv -Path "$OutputPath\SystemInfo.csv" -NoTypeInformation }

    Write-SectionHeader -Title "Disk Information" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
    $diskInfo = Get-DiskInformation -ComputerName $ComputerName
    $diskInfo | Format-Table -AutoSize
    if ($ExportCSV) { $diskInfo | Export-Csv -Path "$OutputPath\DiskInfo.csv" -NoTypeInformation }

    Write-SectionHeader -Title "Network Configuration" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
    $networkInfo = Get-NetworkInformation -ComputerName $ComputerName
    $networkInfo | Format-Table -AutoSize
    if ($ExportCSV) { $networkInfo | Export-Csv -Path "$OutputPath\NetworkInfo.csv" -NoTypeInformation }

    Write-SectionHeader -Title "Azure AD Join Status" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
    $azureADJoinStatus = Get-AzureADJoinStatus -ComputerName $ComputerName
    $azureADJoinStatus 

    # Software and Updates
    Write-SectionHeader -Title "SOFTWARE AND UPDATES" -BorderColor Cyan -TextColor White -Width 80 -BorderChar '='

    Write-SectionHeader -Title "Installed Windows Features and Roles" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
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

    Write-SectionHeader -Title "Installed Applications" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
    $appInfo = Get-InstalledApplications -ComputerName $ComputerName
    $appInfo | Format-Table -AutoSize
    if ($ExportCSV) { $appInfo | Export-Csv -Path "$OutputPath\InstalledApplications.csv" -NoTypeInformation }

    if (-not $SkipStore)
    {
        Write-SectionHeader -Title "Modern Windows Applications (Store/UWP Apps)" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
        $storeApps = Get-WindowsStoreApps -ComputerName $ComputerName
        $storeApps | Format-Table -AutoSize
        if ($ExportCSV) { $storeApps | Export-Csv -Path "$OutputPath\WindowsStoreApps.csv" -NoTypeInformation }
    }

    Write-SectionHeader -Title "Installed Windows Updates" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
    $updateInfo = Get-WindowsUpdateInfo -ComputerName $ComputerName
    $updateInfo | Format-Table -AutoSize
    if ($ExportCSV) { $updateInfo | Export-Csv -Path "$OutputPath\WindowsUpdates.csv" -NoTypeInformation }

    # Network and Sharing
    Write-SectionHeader -Title "NETWORK AND SHARING" -BorderColor Cyan -TextColor White -Width 80 -BorderChar '='

    Write-SectionHeader -Title "File Shares" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
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

    Write-SectionHeader -Title "Printer Information" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
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

    # Security and Automation
    Write-SectionHeader -Title "SECURITY AND AUTOMATION" -BorderColor Cyan -TextColor White -Width 80 -BorderChar '='

    Write-SectionHeader -Title "Custom Firewall Rules" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
    Write-Host "List of Custom Created Firewall Rules" -ForegroundColor Green
    Get-FirewallPortRules | Format-Table -AutoSize -Wrap

    Write-SectionHeader -Title "Custom Scheduled Tasks" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
    Write-Host "List of All Custom Created Scheduled Tasks" -ForegroundColor Green
    Get-NonMicrosoftScheduledTasks | Format-Table -AutoSize

    # Domain Management (if applicable)
    $roleInstalled = Get-WindowsFeature -Name AD-Domain-Services
    if ($roleInstalled.Installed)
    {
        Write-SectionHeader -Title "DOMAIN MANAGEMENT" -BorderColor Cyan -TextColor White -Width 80 -BorderChar '='

        if ($featuresInfo.Roles.Name -contains "DHCP")
        {
            Write-SectionHeader -Title "DHCP Information" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
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
            Write-SectionHeader -Title "DNS Server Information" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
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

        if ($IncludeAD)
        {
            Write-SectionHeader -Title "Active Directory Information" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
            $isDomainController = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
            if ($isDomainController)
            {
                $adInfo = Get-ActiveDirectoryInfo -ComputerName $ComputerName -ErrorAction SilentlyContinue
                if ($adInfo)
                {
                    Write-Host "DOMAIN CONTROLLERS:" -ForegroundColor Yellow
                    $adInfo.DomainControllers | Format-Table -AutoSize
                    Write-Host "FSMO ROLES:" -ForegroundColor Yellow
                    $adInfo.FSMORoles | Format-List
                    Write-Host "Domain Functional Level: $($adInfo.DomainFunctionalLevel)" -ForegroundColor Cyan
                    Write-Host "Forest Functional Level: $($adInfo.ForestFunctionalLevel)" -ForegroundColor Cyan
                    Write-Host "Tombstone Lifetime: $($adInfo.TombstoneLifetime) days" -ForegroundColor Cyan
                    Write-Host "SERVERS IN DOMAIN: $($adInfo.allServers.count)" -ForegroundColor Cyan
                    Write-Host "Total AD Users: $($adInfo.TotalADUsers)" -ForegroundColor Cyan
                    Write-Host "AD Recyclebin: $($adInfo.ADRecyclebin)" -ForegroundColor Cyan
                    Write-Host "Azure AD Join Status: $($adInfo.AzureADJoinStatus)" -ForegroundColor Cyan
                    Write-SectionHeader -Title "List of All Servers in Domain" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
                    $adInfo.AllServers | Format-Table -AutoSize
                    Write-SectionHeader -Title "AD User Report" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
                    Write-Host "USER FOLDERS INFORMATION:" -ForegroundColor Yellow
                    $adInfo.UserFolderReport | Format-Table -AutoSize
                    Write-Host "LOGON SCRIPTS IN SYSVOL:" -ForegroundColor Yellow
                    $adInfo.SysvolScripts | Format-Table -AutoSize
                    Write-Host "PRIVILEGED USERS:" -ForegroundColor Yellow
                    $adInfo.PrivilegedUsers | Format-Table -AutoSize

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

        Write-SectionHeader -Title "Active Directory Hygiene" -BorderColor Green -TextColor White -Width 80 -BorderChar '-'
        Write-Host "List of users who have been inactive for 90 days or more" -ForegroundColor Green
        Get-InactiveUsers90Daysplus

        Write-Host "List of inactive computers for 90 days or more" -ForegroundColor Green
        Get-InactiveComputers90Daysplus

        Write-Host "List of users who have never logged on using their accounts" -ForegroundColor Green
        Get-AdAccountWithNoLogin

        Write-Host "List of users who have no Password set" -ForegroundColor Green
        Get-NoPasswordRequiredUsers

        Write-Host "List of Expired user accounts are as follows" -ForegroundColor Green
        Get-ExpiredUseraccounts

        Write-Host "List of users whose password is set to never expire" -ForegroundColor Green
        Get-PasswordNeverExpiresUsers

        Write-Host "List of Admin Accounts whose passwords are older than 1 year" -ForegroundColor Green
        Get-OldAdminPasswords

        Write-Host "List of empty groups in Active Directory" -ForegroundColor Green
        Get-EmptyADGroups

        Write-Host "List of AD Groups and their member count" -ForegroundColor Green
        Get-ADGroupsWithMemberCount

        # Group Policy Information
        Write-SectionHeader -Title "GROUP POLICY INFORMATION" -BorderColor Cyan -TextColor White -Width 80 -BorderChar '='
        $GPOName = Get-GPOInformation
        $GPOName | Format-Table -AutoSize
        if ($ExportCSV) { $GPOName | Export-Csv -Path "$OutputPath\GPOInfo.csv" -NoTypeInformation }

        Write-Host "List of Group policies that are not being used" -ForegroundColor Green
        Get-UnusedGPOs

        Write-Host "List of GPO's and their respective connections in the domain" -ForegroundColor Green
        Get-GpoConnections

        Write-Host "A comprehensive report on GPO's in the domain" -ForegroundColor Green
        Get-GPOComprehensiveReport | Format-Table -Property GPOName, LinkEnabled, Enforced, GPOStatus, CreatedTime, ModifiedTime, LinkScope -AutoSize
    }
    else
    {
        Write-Warning "This is Not a Domain Controller."
    }

    if ($ExportCSV)
    {
        Write-Host "`nInventory data exported to: $OutputPath" -ForegroundColor Green
    }

    #endregion Data Collection and Output
}
#========================================================== Script Execution ==================================================================
#region Script Execution
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
#endregion Script Execution
#========================================================== End of Script =====================================================================