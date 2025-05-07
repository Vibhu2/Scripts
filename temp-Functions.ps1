function Get-inactiveUsers90Daysplus
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
Get-inactiveUsers90Daysplus

#_________________________________________________________________________________________________________________________________________

function Get-inactiveComputers90Daysplus
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
Get-inactiveComputers90Daysplus

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
get-AdAccountWithNoLogin

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

# Run the function
Get-NoPasswordRequiredUsers


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
Get-OldAdminPasswords

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

# Run the function
Get-EmptyADGroups

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

# Run the function
Get-ADGroupsWithMemberCount

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

# Run the function
Get-UnusedGPOs


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
get-GpoConnections
#_________________________________________________________________________________________________________________________________________
function Get-GPOComprehensiveReport
{
    [CmdletBinding()]
    param(
        [Parameter(HelpMessage = "Show all GPOs (both linked and unlinked)")]
        [switch]$ShowAll = $false,
        
        [Parameter(HelpMessage = "Show only unlinked GPOs")]
        [switch]$ShowUnlinked = $false,
        
        [Parameter(HelpMessage = "Show only linked GPOs")]
        [switch]$ShowLinked = $false,
        
        [Parameter(HelpMessage = "Export results to CSV")]
        [switch]$ExportCSV,
        
        [Parameter(HelpMessage = "Path to export CSV file")]
        [string]$CSVPath = ".\GPO_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
        
        [Parameter(HelpMessage = "Search for GPOs containing this text in their name")]
        [string]$NameFilter = "",
        
        [Parameter(HelpMessage = "Show GPOs modified after this date")]
        [DateTime]$ModifiedAfter,
        
        [Parameter(HelpMessage = "Show GPOs modified before this date")]
        [DateTime]$ModifiedBefore
    )
    
    Write-Host "`n===== Group Policy Object (GPO) Report =====" -ForegroundColor Cyan
    Write-Host "Domain: $((Get-WmiObject Win32_ComputerSystem).Domain)" -ForegroundColor Cyan
    Write-Host "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "Run by: $($env:USERNAME) on $($env:COMPUTERNAME)" -ForegroundColor Cyan
    Write-Host "======================================`n" -ForegroundColor Cyan
    
    try
    {
        Import-Module GroupPolicy -ErrorAction Stop
        Write-Verbose "GroupPolicy module loaded successfully"
    }
    catch
    {
        Write-Error "Failed to load GroupPolicy module: $_"
        return
    }
    
    $allGPOs = @()
    $linkedGPOs = @()
    $unlinkedGPOs = @()
    
    # If no filter switches are specified, show all GPOs
    if (-not $ShowAll -and -not $ShowUnlinked -and -not $ShowLinked)
    {
        $ShowAll = $true
    }
    
    try
    {
        # Get all GPOs and show progress
        Write-Host "Retrieving Group Policy Objects..." -ForegroundColor Yellow
        $gpos = Get-GPO -All
        
        if (-not $gpos)
        {
            Write-Warning "No Group Policy Objects found in the domain."
            return
        }
        
        $totalGPOs = $gpos.Count
        Write-Verbose "Found $totalGPOs GPOs in total."
        $processedCount = 0
        
        # Process each GPO
        foreach ($gpo in $gpos)
        {
            $processedCount++
            Write-Progress -Activity "Processing GPOs" -Status "Processing $processedCount of $totalGPOs" -PercentComplete (($processedCount / $totalGPOs) * 100)
            
            # Apply name filter if specified
            if ($NameFilter -and $gpo.DisplayName -notlike "*$NameFilter*")
            {
                continue
            }
            
            # Apply date filters if specified
            if ($ModifiedAfter -and $gpo.ModificationTime -lt $ModifiedAfter)
            {
                continue
            }
            if ($ModifiedBefore -and $gpo.ModificationTime -gt $ModifiedBefore)
            {
                continue
            }
            
            # Use the GPO object's GenerateReport method to get XML report
            [string]$xmlReport = $gpo.GenerateReport('XML')
            [xml]$doc = $xmlReport
            
            # Process links
            $links = @()
            if ($doc.GPO.LinksTo.Link)
            {
                foreach ($link in $doc.GPO.LinksTo.Link)
                {
                    $links += [PSCustomObject]@{
                        Target     = $link.SOMPath
                        Enabled    = $link.Enabled
                        NoOverride = $link.NoOverride
                    }
                }
            }
            $linkCount = $links.Count
            
            # Create GPO object
            $gpoObject = [PSCustomObject]@{
                Name            = $gpo.DisplayName
                IsLinked        = ($linkCount -gt 0)
                LinkCount       = $linkCount
                Status          = $gpo.GpoStatus
                Modified        = $gpo.ModificationTime
                Created         = $gpo.CreationTime
                UserVersion     = [int]$doc.GPO.UserVersion
                ComputerVersion = [int]$doc.GPO.ComputerVersion
                Description     = $gpo.Description
                ID              = $gpo.Id
                Links           = $links
            }
            
            # Add to appropriate arrays
            $allGPOs += $gpoObject
            
            if ($linkCount -gt 0)
            {
                $linkedGPOs += $gpoObject
            }
            else
            {
                $unlinkedGPOs += $gpoObject
            }
        }
        
        Write-Progress -Activity "Processing GPOs" -Completed
        
        # Display results based on switches
        if ($ShowAll -or $ShowLinked)
        {
            Write-Host "`n--- Linked GPOs ($($linkedGPOs.Count)) ---" -ForegroundColor Green
            if ($linkedGPOs.Count -gt 0)
            {
                # Format linked GPOs table with ID at the end, sorted by Modified date
                $linkedGPOs | 
                    Sort-Object Modified -Descending | 
                    Format-Table Name, Status, UserVersion, ComputerVersion, LinkCount, Created, Modified, ID -AutoSize
                
                # Show detailed link information
                Write-Host "`n--- GPO Links Detail ---" -ForegroundColor Green
                foreach ($gpo in ($linkedGPOs | Sort-Object Modified -Descending))
                {
                    Write-Host "`nGPO: $($gpo.Name) (Modified: $($gpo.Modified))" -ForegroundColor Yellow
                    $gpo.Links | Format-Table Target, Enabled, NoOverride -AutoSize
                }
            }
            else
            {
                Write-Host "No linked GPOs found." -ForegroundColor Yellow
            }
        }
        
        if ($ShowAll -or $ShowUnlinked)
        {
            Write-Host "`n--- Unlinked GPOs ($($unlinkedGPOs.Count)) ---" -ForegroundColor Magenta
            if ($unlinkedGPOs.Count -gt 0)
            {
                # Format unlinked GPOs table with ID at the end, sorted by Modified date
                $unlinkedGPOs | 
                    Sort-Object Modified -Descending | 
                    Format-Table Name, Status, UserVersion, ComputerVersion, Created, Modified, ID -AutoSize
            }
            else
            {
                Write-Host "✅ No unlinked GPOs found." -ForegroundColor Green
            }
        }
        
        # Export to CSV if requested
        if ($ExportCSV)
        {
            Write-Verbose "Exporting GPO data to CSV: $CSVPath"
            
            # Create expanded CSV data with link information
            $csvData = @()
            foreach ($gpo in $allGPOs)
            {
                if ($gpo.LinkCount -gt 0)
                {
                    foreach ($link in $gpo.Links)
                    {
                        $csvData += [PSCustomObject]@{
                            Name            = $gpo.Name
                            Status          = $gpo.Status
                            UserVersion     = $gpo.UserVersion
                            ComputerVersion = $gpo.ComputerVersion
                            Created         = $gpo.Created
                            Modified        = $gpo.Modified
                            Description     = $gpo.Description
                            IsLinked        = $true
                            LinkTarget      = $link.Target
                            LinkEnabled     = $link.Enabled
                            LinkNoOverride  = $link.NoOverride
                            ID              = $gpo.ID
                        }
                    }
                }
                else
                {
                    $csvData += [PSCustomObject]@{
                        Name            = $gpo.Name
                        Status          = $gpo.Status
                        UserVersion     = $gpo.UserVersion
                        ComputerVersion = $gpo.ComputerVersion
                        Created         = $gpo.Created
                        Modified        = $gpo.Modified
                        Description     = $gpo.Description
                        IsLinked        = $false
                        LinkTarget      = $null
                        LinkEnabled     = $null
                        LinkNoOverride  = $null
                        ID              = $gpo.ID
                    }
                }
            }
            
            $csvData | Export-Csv -Path $CSVPath -NoTypeInformation
            Write-Host "`nGPO report exported to: $CSVPath" -ForegroundColor Cyan
        }
        
        # Return summary information
        Write-Host "`n=== Summary ===" -ForegroundColor Cyan
        Write-Host "Total GPOs: $($allGPOs.Count)" -ForegroundColor White
        Write-Host "Linked GPOs: $($linkedGPOs.Count)" -ForegroundColor Green
        Write-Host "Unlinked GPOs: $($unlinkedGPOs.Count)" -ForegroundColor $(if ($unlinkedGPOs.Count -gt 0) { "Magenta" } else { "Green" })
        Write-Host "==============================================" -ForegroundColor Cyan
        
        # Return the GPO objects for pipeline usage
        return $allGPOs | Sort-Object Modified -Descending
    }
    catch
    {
        Write-Error "Error processing GPOs: $_"
    }
}

# Example usage (uncomment what you need)
# Default usage - shows all GPOs and sorts by modified date
Get-GPOComprehensiveReport | Format-Table -AutoSize
#_________________________________________________________________________________________________________________________________________