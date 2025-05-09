function Get-FirewallPortRules {
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage="Include rules where Action = Block")]
        [switch]$IncludeBlocked,
        
        [Parameter(HelpMessage="Include rules that are not enabled")]
        [switch]$IncludeDisabled,
        
        [Parameter(HelpMessage="Filter by specific protocol (TCP, UDP, Any)")]
        [ValidateSet("TCP", "UDP", "Any", IgnoreCase = $true)]
        [string]$Protocol,
        
        [Parameter(HelpMessage="Filter by specific port number")]
        [string]$Port,
        
        [Parameter(HelpMessage="Show additional rule details including rule description")]
        [switch]$Detailed,
        
        [Parameter(HelpMessage="Export results to CSV file")]
        [string]$ExportCSV
    )

    # Display processing message
    Write-Verbose "Retrieving firewall rules with filters - Blocked: $IncludeBlocked, Disabled: $IncludeDisabled, Protocol: $($Protocol ?? 'Any'), Port: $($Port ?? 'Any')"
    
    # Get all matching firewall rules
    $rules = Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {
        $_.Direction -eq 'Inbound' -and
        ($IncludeBlocked -or $_.Action -eq 'Allow') -and
        ($IncludeDisabled -or $_.Enabled -eq $true)
    }
    
    Write-Verbose "Found $($rules.Count) matching base firewall rules"
    
    $results = [System.Collections.ArrayList]::new()
    $processedCount = 0
    
    foreach ($rule in $rules) {
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
        if ($portFilters) {
            foreach ($filter in $portFilters) {
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
                    Profiles    = ($rule.Profile -split ", " | ForEach-Object { $_.Substring(0,1) }) -join ""
                    Action      = $rule.Action
                    Protocol    = if ($filter.Protocol -eq "Any") { "Any" } else { $filter.Protocol }
                    LocalPort   = if ($filter.LocalPort -eq "Any") { "Any" } else { $filter.LocalPort }
                    RemotePort  = if ($filter.RemotePort -eq "Any") { "Any" } else { $filter.RemotePort }
                    Program     = if ($appFilter.Program -eq "*") { "Any" } else { Split-Path $appFilter.Program -Leaf }
                    ProgramPath = if ($appFilter.Program -eq "*") { "Any" } else { $appFilter.Program }
                }
                
                # Add detailed properties if requested
                if ($Detailed) {
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
        elseif ($Detailed) {
            $resultObj = [PSCustomObject]@{
                RuleID      = $rule.Name
                Name        = $rule.DisplayName
                Enabled     = if ($rule.Enabled -eq $true) { "Yes" } else { "No" }
                Direction   = $rule.Direction
                Profiles    = ($rule.Profile -split ", " | ForEach-Object { $_.Substring(0,1) }) -join ""
                Action      = $rule.Action
                Protocol    = "N/A"
                LocalPort   = "N/A"
                RemotePort  = "N/A"
                Program     = if ($appFilter.Program -eq "*") { "Any" } else { Split-Path $appFilter.Program -Leaf }
                ProgramPath = if ($appFilter.Program -eq "*") { "Any" } else { $appFilter.Program }
                Description = $rule.Description
                Group       = $rule.Group
                LocalAddress = ($addressFilter.LocalAddress -join ", ")
                RemoteAddress = ($addressFilter.RemoteAddress -join ", ")
                Authentication = $securityFilter.Authentication
                Encryption = $securityFilter.Encryption
            }
            
            [void]$results.Add($resultObj)
        }
    }
    
    Write-Progress -Activity "Processing Firewall Rules" -Completed
    
    # Export to CSV if requested
    if ($ExportCSV) {
        try {
            $results | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8
            Write-Host "Results exported to $ExportCSV" -ForegroundColor Green
        }
        catch {
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
    
    if ($Protocol) {
        Write-Host "$Protocol protocol rules: $(($results | Where-Object { $_.Protocol -eq $Protocol }).Count)" -ForegroundColor Cyan
    }
    
    return $results
}

# Example usage:
# Get all enabled "Allow" rules
 Get-FirewallPortRules | Sort-Object -Property Name | Format-Table -AutoSize -Wrap
