# Pre-deploy hook for DnsTools (runs client-side, non-elevated, BEFORE Deploy-Modules copies the tree).
#
# Refreshes the shipped root-hints baseline (Helpers\RootHints-Cache.xml) from a live, TLS-verified fetch of
# named.root, so the freshly deployed module carries a current root list. The baseline is the TRUSTED offline
# fallback the resolver uses when it cannot reach internic, so keeping it current at deploy time means an
# offline machine bootstraps from a recent list instead of a stale one.
#
# Best-effort: if the verified fetch fails (e.g. no internet at deploy time), the existing committed baseline
# is left untouched and the deploy proceeds. Get-RootHints.ps1 does the fetch + parse, and on failure simply
# returns the current baseline, so re-saving it is a no-op.

$ErrorActionPreference = 'Continue'

$helper   = Join-Path -Path $PSScriptRoot -ChildPath '..\Helpers\Get-RootHints.ps1'
$baseline = Join-Path -Path $PSScriptRoot -ChildPath '..\Helpers\RootHints-Cache.xml'

try
{
	$result = . $helper
	if ($result -and $result.RootServerAddresses)
	{
		$result | Export-Clixml -LiteralPath $baseline -Force
		Write-Host ('  root hints baseline refreshed ({0} addresses).' -f @($result.RootServerAddresses).Count) -ForegroundColor Green
	}
	else
	{Write-Warning '  root hints fetch returned nothing - baseline kept as-is.'}
}
catch
{Write-Warning ('  root hints baseline NOT refreshed (kept existing): {0}' -f $_.Exception.Message)}
