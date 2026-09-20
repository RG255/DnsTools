function Initialize-DnssecTrustAnchorFile
{
	<#
	.SYNOPSIS
		Initializes DNSSEC trust anchors from the default trust anchor file.

	.DESCRIPTION
		Loads the default DNSSEC trust anchors from the module's trust-anchors.json file.
	#>

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	$trustAnchorPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Helpers\trust-anchors.json'
	Import-DnssecTrustAnchorFile -Path $trustAnchorPath
}
