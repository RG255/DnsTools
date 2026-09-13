# Run-GenerateFixtures.ps1
# Wrapper script that sets up the environment for fixture generation

param(
	[string]$OutputPath
)

# Export all functions for fixture generation
$env:DNSTOOLS_EXPORT_ALL = '1'

# Build parameters for Generate-Fixtures.ps1
$scriptPath = Join-Path $PSScriptRoot 'Generate-Fixtures.ps1'

if ($OutputPath) {
	& $scriptPath -OutputPath $OutputPath
} else {
	& $scriptPath
}
