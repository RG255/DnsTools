function Update-DnssecTrustAnchors
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
        Update-DnssecTrustAnchors
        Fetches and displays the current IANA root trust anchors.

    .EXAMPLE
        Update-DnssecTrustAnchors -Force
        Updates the module's trust-anchors.json with current IANA root anchors.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(DontShow)]
        [string]$OutputPath,

        [switch]$Force
    )

    $ianaUrl = 'https://data.iana.org/root-anchors/root-anchors.xml'

    try {
        Write-Verbose "Fetching trust anchors from $ianaUrl"
        $response = Invoke-WebRequest -Uri $ianaUrl -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        [xml]$xml = $response.Content
    }
    catch {
        throw "Failed to fetch trust anchors from IANA: $($_.Exception.Message)"
    }

    # Parse the XML to extract trust anchors
    $anchors = @()
    foreach ($keyDigest in $xml.TrustAnchor.KeyDigest) {
        # Only include valid (not revoked) anchors
        if ($keyDigest.validUntil -and ([datetime]$keyDigest.validUntil -lt [datetime]::UtcNow)) {
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
    if ($Force -or $PSCmdlet.ShouldProcess($OutputPath, "Update trust anchors file")) {
        $json = $anchors | ConvertTo-Json -Depth 10
        Set-Content -Path $OutputPath -Value $json -Encoding UTF8
        Write-Host "Trust anchors written to: $OutputPath" -ForegroundColor Yellow

        # Reload the trust anchors into memory
        Import-DnssecTrustAnchors -Path $OutputPath
        Write-Host "Trust anchors reloaded into memory" -ForegroundColor Yellow
    }

    return $anchors
}
