function get-GPOinformation{
       
    # Get the GPO information
    if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue))
    {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    $gpo = Get-GPO -All  | Get-GPO -All | Select-Object Id, Displayname, GpoStatus, CreationTime, ModificationTime, Description | Sort-Object -Property ModificationTime | Format-Table -AutoSize

}
else {
    Write-Error "GPO '$GPOName' not found."
}
}
