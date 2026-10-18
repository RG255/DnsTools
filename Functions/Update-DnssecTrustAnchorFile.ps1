function Update-DnssecTrustAnchorFile
{
	<#
    .SYNOPSIS
        Updates DNSSEC trust anchors from IANA's root-anchors.xml.

    .DESCRIPTION
        Fetches the current DNSSEC root trust anchors from IANA's official source
        and updates the module's trust-anchors.json file.

        The root trust anchors are published by IANA at:
        https://data.iana.org/root-anchors/root-anchors.xml

        Root key rollovers are rare (the last one was in 2018), but when they occur,
        this function can be used to update the local trust anchors.

    .PARAMETER OutputPath
        Optional path to write the updated trust anchors JSON file.
        Defaults to the module's Helpers\trust-anchors.json file.

    .PARAMETER Force
        Overwrite the existing trust anchors file without prompting.

    .EXAMPLE
        Update-DnssecTrustAnchorFile
        Fetches and displays the current IANA root trust anchors.

    .EXAMPLE
        Update-DnssecTrustAnchorFile -Force
        Updates the module's trust-anchors.json with current IANA root anchors.
    #>
	[CmdletBinding(SupportsShouldProcess)]
	param(
		[Parameter(DontShow)]
		[string]$OutputPath,

		[switch]$Force,

		# Escape hatch for a machine that cannot build the signing certificate's chain (offline CA store, TLS-inspecting proxy).
		# The anchors are then trusted on the strength of the HTTPS download alone - say so to the user.
		[switch]$SkipSignatureCheck
	)

	$ianaUrl = 'https://data.iana.org/root-anchors/root-anchors.xml'
	$signatureUrl = 'https://data.iana.org/root-anchors/root-anchors.p7s'

	try {
		Write-Verbose "Fetching trust anchors from $ianaUrl"
		$response = Invoke-WebRequest -Uri $ianaUrl -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
		# The exact bytes IANA sent: the signature covers them, so they are verified before they are parsed.
		$xmlBytes = $response.RawContentStream.ToArray()
		[xml]$xml = [System.Text.Encoding]::UTF8.GetString($xmlBytes).TrimStart([char]0xFEFF)
	}
	catch {
		throw "Failed to fetch trust anchors from IANA: $($_.Exception.Message)"
	}

	# 0.8: verify IANA's detached PKCS#7 signature (root-anchors.p7s) over the XML, including the signing certificate's
	# chain. A plain HTTPS download is the only thing between an interceptor and the root of trust for every DNSSEC
	# verdict this module gives.
	if (-not $SkipSignatureCheck) {
		try {
			Add-Type -AssemblyName System.Security
			$sigResponse = Invoke-WebRequest -Uri $signatureUrl -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
			$sigBytes = $sigResponse.RawContentStream.ToArray()
			$contentInfo = New-Object -TypeName System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList (, $xmlBytes)
			$cms = New-Object -TypeName System.Security.Cryptography.Pkcs.SignedCms -ArgumentList $contentInfo, $true
			$cms.Decode($sigBytes)
			# The signature itself must verify over the exact bytes downloaded.
			$cms.CheckSignature($true)

			# The signing certificate (CN=DNSSEC Trust Anchor Verification) is issued by ICANN's own root, which is not in
			# any operating-system store, so the OS cannot validate it. Build the chain from the certificates embedded in the
			# signature and require that it ends at the ICANN Root CA whose SHA-256 thumbprint is pinned here (recorded
			# 2026-10-18 from IANA's published signature; compare it with ICANN's published fingerprint if in doubt).
			$pinnedIcannRoot = 'AEE89906D7CC60C5E151F3BB923ABF8A1B28DC855D5E2127CB524EAD4AAD603D'
			$signerCert = $cms.SignerInfos[0].Certificate
			$x509Chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
			$x509Chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
			$x509Chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
			foreach ($embedded in $cms.Certificates)
			{[void]$x509Chain.ChainPolicy.ExtraStore.Add($embedded)}
			[void]$x509Chain.Build($signerCert)
			if ($x509Chain.ChainElements.Count -lt 2)
			{throw 'the signing certificate does not chain to a CA certificate'}
			$rootCert = $x509Chain.ChainElements[$x509Chain.ChainElements.Count - 1].Certificate
			$sha = [System.Security.Cryptography.SHA256]::Create()
			try
			{$rootThumb = [BitConverter]::ToString($sha.ComputeHash($rootCert.RawData)).Replace('-', '')}
			finally
			{$sha.Dispose()}
			if ($rootThumb -ne $pinnedIcannRoot)
			{throw "the signing chain ends at an unexpected root (SHA-256 $rootThumb), not the pinned ICANN Root CA"}
			foreach ($chainStatus in $x509Chain.ChainStatus)
			{
				if ($chainStatus.Status -band [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NotTimeValid)
				{throw "a certificate in the signing chain is outside its validity period: $($chainStatus.StatusInformation)"}
			}
			Write-Verbose ('IANA signature verified (signer: {0}; root: {1})' -f $signerCert.Subject, $rootCert.Subject)
		}
		catch {
			throw "The IANA signature on root-anchors.xml could not be verified, so the downloaded anchors were NOT used: $($_.Exception.Message) (use -SkipSignatureCheck only if you accept trusting the HTTPS download alone)"
		}
	}
	# Parse the XML to extract trust anchors
	$anchors = @()
	foreach ($keyDigest in $xml.TrustAnchor.KeyDigest) {
		# Only include valid (not revoked) anchors
		# GetAttribute, not dot access: validUntil is an XML ATTRIBUTE that is absent on the current anchors, and
		# dot access to a missing attribute throws under Set-StrictMode (0.8 fix - the update never completed).
		$validUntil = $keyDigest.GetAttribute('validUntil')
		if ($validUntil -and ([datetime]$validUntil -lt [datetime]::UtcNow)) {
			Write-Verbose "Skipping expired anchor KeyTag $($keyDigest.KeyTag)"
			continue
		}

		$anchor = [PSCustomObject]@{
			Zone       = '.'
			KeyTag     = [int]$keyDigest.KeyTag
			Algorithm  = [int]$keyDigest.Algorithm
			DigestType = [int]$keyDigest.DigestType
			DigestHex  = $keyDigest.Digest.Trim().ToUpper()
		}
		$anchors += $anchor
	}

	if ($anchors.Count -eq 0) {
		throw "No valid trust anchors found in IANA response"
	}

	Write-Host "Found $($anchors.Count) valid trust anchor(s):" -ForegroundColor Cyan
	foreach ($a in $anchors) {
		Write-Host "  KeyTag: $($a.KeyTag), Algorithm: $($a.Algorithm), DigestType: $($a.DigestType)" -ForegroundColor Green
	}

	# Determine output path
	if (-not $OutputPath) {
		$OutputPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Helpers\trust-anchors.json'
		# Fallback to Functions folder if Helpers doesn't exist
		if (-not (Test-Path (Split-Path $OutputPath -Parent))) {
			$OutputPath = Join-Path -Path $PSScriptRoot -ChildPath 'trust-anchors.json'
		}
	}

	# Write to file if Force or user confirms
	# 0.8: -Force only suppresses the confirmation prompt; it used to short-circuit ShouldProcess, so -Force -WhatIf still overwrote the file.
	if ($Force) { $ConfirmPreference = 'None' }
	if ($PSCmdlet.ShouldProcess($OutputPath, 'Update trust anchors file')) {
		$json = $anchors | ConvertTo-Json -Depth 10
		Set-Content -Path $OutputPath -Value $json -Encoding UTF8
		Write-Host "Trust anchors written to: $OutputPath" -ForegroundColor Yellow

		# Reload the trust anchors into memory
		Import-DnssecTrustAnchorFile -Path $OutputPath
		Write-Host "Trust anchors reloaded into memory" -ForegroundColor Yellow
	}

	return $anchors
}
