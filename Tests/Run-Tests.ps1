# Run-Tests.ps1
# Test runner that sets up the environment for DnsTools testing

param(
    [string]$Path = $PSScriptRoot,
    [string]$Output = 'Normal',
    [string]$TagFilter,
    [string]$ExcludeTagFilter
)

# Export all functions for testing
$env:DNSTOOLS_EXPORT_ALL = '1'

# Build Pester parameters
$pesterParams = @{
    Path   = $Path
    Output = $Output
}

if ($TagFilter) {
    $pesterParams['TagFilter'] = $TagFilter
}
if ($ExcludeTagFilter) {
    $pesterParams['ExcludeTagFilter'] = $ExcludeTagFilter
}

# Run tests
Invoke-Pester @pesterParams
