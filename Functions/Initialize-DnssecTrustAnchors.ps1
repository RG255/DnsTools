function Initialize-DnssecTrustAnchors 
{
	$trustAnchorPath = Join-Path -Path $PSScriptRoot -ChildPath 'trust-anchors.json'
	Import-DnssecTrustAnchors -Path $trustAnchorPath
}