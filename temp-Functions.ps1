function Get-GPOComprehensiveReport
{
    <#
    .SYNOPSIS
        Generates a report of Group Policy Objects (GPOs) in the current domain.

    .DESCRIPTION
        Retrieves and displays details about GPOs, including linked and unlinked policies, with options to filter by name, modification dates, or link status. Supports CSV export.

    .PARAMETER ShowAll
        Display both linked and unlinked GPOs (default if no filter is specified).

    .PARAMETER ShowUnlinked
        Display only unlinked GPOs.

    .PARAMETER ShowLinked
        Display only linked GPOs.

    .PARAMETER ExportCSV
        Export the report to a CSV file.

    .PARAMETER CSVPath
        Path for the CSV file. Defaults to ".\GPO_Report_YYYYMMDD_HHMMSS.csv".

    .PARAMETER NameFilter
        Filter GPOs by name (supports wildcards).

    .PARAMETER ModifiedAfter
        Show GPOs modified after the specified date.

    .PARAMETER ModifiedBefore
        Show GPOs modified before the specified date.

    .EXAMPLE
        Get-GPOComprehensiveReport -ShowLinked
        Displays only linked GPOs.

    .EXAMPLE
        Get-GPOComprehensiveReport -NameFilter "Workstation*" -ExportCSV
        Exports GPOs with names matching "Workstation*" to a CSV file.

    .NOTES
        Requires the GroupPolicy module and appropriate permissions.
    #>
    [CmdletBinding()]
    param(
        [switch]$ShowAll,
        [switch]$ShowUnlinked,
        [switch]$ShowLinked,
        [switch]$ExportCSV,
        [ValidateScript({ Test-Path -Path (Split-Path $_ -Parent) -PathType Container })]
        [string]$CSVPath = ".\GPO_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
        [string]$NameFilter,
        [DateTime]$ModifiedAfter,
        [DateTime]$ModifiedBefore
    )

    # Header
    Write-Host "`n=== Group Policy Object Report ===" -ForegroundColor Cyan
    Write-Host "Domain: $((Get-WmiObject Win32_ComputerSystem).Domain)"
    Write-Host "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host "Run by: $env:USERNAME on $env:COMPUTERNAME"
    Write-Host "===============================`n" -ForegroundColor Cyan

    try
    {
        Import-Module GroupPolicy -ErrorAction Stop
        Write-Verbose "GroupPolicy module loaded."
    }
    catch
    {
        Write-Error "Failed to load GroupPolicy module: $_"
        return
    }

    # Default to ShowAll if no filter switches are specified
    if (-not ($ShowAll -or $ShowUnlinked -or $ShowLinked))
    {
        $ShowAll = $true
    }

    try
    {
        Write-Host "Retrieving GPOs..." -ForegroundColor Yellow
        $gpos = Get-GPO -All -ErrorAction Stop

        if (-not $gpos)
        {
            Write-Warning "No GPOs found in the domain."
            return
        }

        $allGPOs = @()
        $linkedGPOs = @()
        $unlinkedGPOs = @()

        # Process each GPO
        foreach ($gpo in $gpos)
        {
            # Apply filters
            if ($NameFilter -and $gpo.DisplayName -notlike "*$NameFilter*") { continue }
            if ($ModifiedAfter -and $gpo.ModificationTime -lt $ModifiedAfter) { continue }
            if ($ModifiedBefore -and $gpo.ModificationTime -gt $ModifiedBefore) { continue }

            # Get XML report
            [xml]$xmlReport = $gpo.GenerateReport('XML')

            # Process links
            $links = @($xmlReport.GPO.LinksTo.Link | ForEach-Object {
                    [PSCustomObject]@{
                        Target     = $_.SOMPath
                        Enabled    = $_.Enabled -eq 'true'
                        NoOverride = $_.NoOverride -eq 'true'
                    }
                })

            # Create GPO object
            $gpoObject = [PSCustomObject]@{
                Name        = $gpo.DisplayName
                IsLinked    = $links.Count -gt 0
                LinkCount   = $links.Count
                Status      = $gpo.GpoStatus
                Modified    = $gpo.ModificationTime
                Created     = $gpo.CreationTime
                UserVersion = [int]($xmlReport.GPO.UserVersion.Value ?? 0)
                ComputerVersion = [int]($xmlReport.GPO.ComputerVersion.Value ?? 0)
                Description     = $gpo.Description
                ID              = $gpo.Id
                Links           = $links
            }

            $allGPOs += $gpoObject
            if ($gpoObject.IsLinked)
            {
                $linkedGPOs += $gpoObject
            }
            else
            {
                $unlinkedGPOs += $gpoObject
            }
        }

        # Display linked GPOs
        if ($ShowAll -or $ShowLinked)
        {
            Write-Host "`n--- Linked GPOs ($($linkedGPOs.Count)) ---" -ForegroundColor Green
            if ($linkedGPOs)
            {
                $linkedGPOs | Sort-Object Modified -Descending | 
                    Select-Object Name, Status, UserVersion, ComputerVersion, LinkCount, Created, Modified, ID | 
                    Out-Host
                foreach ($gpo in $linkedGPOs | Sort-Object Modified -Descending)
                {
                    Write-Host "`nGPO: $($gpo.Name) | ID: $($gpo.ID)" -ForegroundColor Yellow
                    if ($gpo.Links)
                    {
                        $gpo.Links | Select-Object Target, Enabled, NoOverride | Out-Host
                    }
                    else
                    {
                        Write-Host "  No links found." -ForegroundColor Gray
                    }
                }
            }
            else
            {
                Write-Host "No linked GPOs found." -ForegroundColor Yellow
            }
        }

        # Display unlinked GPOs
        if ($ShowAll -or $ShowUnlinked)
        {
            Write-Host "`n--- Unlinked GPOs ($($unlinkedGPOs.Count)) ---" -ForegroundColor Magenta
            if ($unlinkedGPOs)
            {
                $unlinkedGPOs | Sort-Object Modified -Descending | 
                    Select-Object Name, Status, UserVersion, ComputerVersion, Created, Modified, ID | 
                    Out-Host
            }
            else
            {
                Write-Host "No unlinked GPOs found." -ForegroundColor Green
            }
        }

        # Export to CSV
        if ($ExportCSV)
        {
            $csvData = @()
            foreach ($gpo in $allGPOs)
            {
                if ($gpo.Links)
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
            Write-Host "`nReport exported to: $CSVPath" -ForegroundColor Cyan
        }

        # Summary
        Write-Host "`n=== Summary ===" -ForegroundColor Cyan
        Write-Host "Total GPOs: $($allGPOs.Count)"
        Write-Host "Linked GPOs: $($linkedGPOs.Count)"
        Write-Host "Unlinked GPOs: $($unlinkedGPOs.Count)"
        Write-Host "===============================`n" -ForegroundColor Cyan

        # Return GPO objects for pipeline
        return $allGPOs
    }
    catch {
        Write-Error "Error processing GPOs: $_"
    }

