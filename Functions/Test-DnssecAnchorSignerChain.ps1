function Test-DnssecAnchorSignerChain
{
	<#
		.SYNOPSIS
		Checks that the certificate that signed IANA's root-anchors.xml chains to the pinned ICANN Root CA.

		.DESCRIPTION
		Added in 0.8 (split out of Update-DnssecTrustAnchorFile so it can be tested without the network). The signing
		certificate is issued by ICANN's own root, which no operating-system store trusts, so the chain is built from the
		certificates embedded in the signature and must end at a root whose SHA-256 thumbprint is the pinned value.

		A thumbprint match alone is not enough: an attacker can sign with their own key, give the leaf the ICANN root as
		its ISSUER NAME, and embed the genuine (public) root certificate beside it. The chain then ends at the pinned root
		but the leaf is not signed by it, which the chain engine reports as NotSignatureValid. So every chain status except
		UntrustedRoot (which the pin replaces) is fatal, and the chain must have been built.

		.PARAMETER SignerCertificate
		The signing certificate (X509Certificate2).

		.PARAMETER ExtraCertificate
		The other certificates embedded in the signature.

		.PARAMETER PinnedRootThumbprint
		SHA-256 thumbprint (hex, no separators) the chain must end at.

		.OUTPUTS
		[PSCustomObject] with Valid ([bool]), Reason ([string]) and RootSubject ([string]).
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		[System.Security.Cryptography.X509Certificates.X509Certificate2]$SignerCertificate,

		[AllowEmptyCollection()]
		[System.Security.Cryptography.X509Certificates.X509Certificate2[]]$ExtraCertificate = @(),

		[Parameter(Mandatory)]
		[string]$PinnedRootThumbprint
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	$chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
	try
	{
		$chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
		$chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
		foreach ($extra in $ExtraCertificate)
		{[void]$chain.ChainPolicy.ExtraStore.Add($extra)}

		$built = $chain.Build($SignerCertificate)
		if ($chain.ChainElements.Count -lt 2)
		{return [pscustomobject]@{ Valid = $false; Reason = 'the signing certificate does not chain to a CA certificate'; RootSubject = '' }}

		$rootCert = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
		$sha = [System.Security.Cryptography.SHA256]::Create()
		try
		{$rootThumb = [BitConverter]::ToString($sha.ComputeHash($rootCert.RawData)).Replace('-', '')}
		finally
		{$sha.Dispose()}
		if ($rootThumb -ne $PinnedRootThumbprint.Replace('-', '').ToUpper())
		{return [pscustomobject]@{ Valid = $false; Reason = "the signing chain ends at an unexpected root (SHA-256 $rootThumb), not the pinned ICANN Root CA"; RootSubject = $rootCert.Subject }}

		foreach ($status in $chain.ChainStatus)
		{
			if ($status.Status -ne [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot)
			{return [pscustomobject]@{ Valid = $false; Reason = "the signing certificate chain is not valid ($($status.Status)): $($status.StatusInformation)"; RootSubject = $rootCert.Subject }}
		}
		if (-not $built -and @($chain.ChainStatus).Count -eq 0)
		{return [pscustomobject]@{ Valid = $false; Reason = 'the signing certificate chain could not be built'; RootSubject = $rootCert.Subject }}

		return [pscustomobject]@{ Valid = $true; Reason = 'ok'; RootSubject = $rootCert.Subject }
	}
	catch
	{
		Write-MyCatchAudit -Source 'Test-DnssecAnchorSignerChain: unexpected error building the signing chain' -ErrorRecord $_
		return [pscustomobject]@{ Valid = $false; Reason = "unexpected error: $($_.Exception.Message)"; RootSubject = '' }
	}
	finally
	{$chain.Dispose()}
}
