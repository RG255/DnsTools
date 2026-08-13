function Initialize-DnssecTrustAnchors
{
	<#
	.SYNOPSIS
		Initializes DNSSEC trust anchors from the default trust anchor file.

	.DESCRIPTION
		Loads the default DNSSEC trust anchors from the module's trust-anchors.json file.
	#>

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	$trustAnchorPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Helpers\trust-anchors.json'
	Import-DnssecTrustAnchors -Path $trustAnchorPath
}