function Test-DnssecRrsetSignature
{
	<#
		.SYNOPSIS
		Checks that an RRset carries at least one valid RRSIG made by one of a given set of trusted keys.

		.DESCRIPTION
		Added in 0.8. Unlike Test-DnssecRrsig (which verifies ONE RRSIG against whatever key set it is handed),
		this checks the things that make the answer mean something:

		- the RRSIG covers this RRset's type and is owned by the same name;
		- the RRSIG signer name is the expected zone (so a signature from an unrelated zone is not accepted);
		- EVERY trusted key with a matching tag and algorithm is tried, not just the first (key tags collide);
		- the key is a zone key, protocol 3, not revoked;
		- an unsupported algorithm or a malformed key counts as a failed attempt, never as success.

		.PARAMETER Rrset
		The resource records being verified (one name, one type).

		.PARAMETER Rrsigs
		RRSIG resource records that may cover the RRset (others are ignored).

		.PARAMETER KeyRecords
		DNSKEY resource records the caller already trusts for ZoneName.

		.PARAMETER ZoneName
		The zone whose key must have signed (the required RRSIG signer name).

		.OUTPUTS
		[PSCustomObject] with Valid ([bool]) and Reason ([string]).
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		[psobject[]]$Rrset,

		[Parameter(Mandatory)]
		[AllowEmptyCollection()]
		[psobject[]]$Rrsigs,

		[Parameter(Mandatory)]
		[AllowEmptyCollection()]
		[psobject[]]$KeyRecords,

		[Parameter(Mandatory)]
		[AllowEmptyString()]
		[string]$ZoneName
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	try
	{
		$ownerName = $Rrset[0].Name.TrimEnd('.').ToLower()
		$rrType = [int]$Rrset[0].Type
		$wantSigner = $ZoneName.TrimEnd('.').ToLower()
		$reasons = New-Object -TypeName System.Collections.Generic.List[string]
		$considered = 0
		$verdicts = 0       # attempts that produced a real answer (valid or invalid)
		$unsupported = 0    # RRSIGs whose algorithm this module cannot verify

		foreach ($sigRr in $Rrsigs)
		{
			$sig = $sigRr.RDataObject
			if ($sig -isnot [DnsRrsigRecord])
			{continue}
			if ([int]$sig.TypeCovered -ne $rrType)
			{continue}
			if ($sigRr.Name.TrimEnd('.').ToLower() -ne $ownerName)
			{continue}

			$considered++

			if ($sig.SignerName.TrimEnd('.').ToLower() -ne $wantSigner)
			{
				$reasons.Add("RRSIG signer '$($sig.SignerName)' is not the expected zone '$ZoneName'")
				continue
			}

			# RFC 4035 5.2: an algorithm we do not implement is "cannot verify", reported apart from "verified and wrong".
			if (-not (Test-DnssecAlgorithmSupported -Algorithm ([int]$sig.Algorithm)))
			{
				$unsupported++
				$reasons.Add("RRSIG algorithm $($sig.Algorithm) is not supported by this module")
				continue
			}

			$candidates = @($KeyRecords | Where-Object -FilterScript {
					$k = $_.RDataObject
					$k -is [DnsDnskeyRecord] -and $k.KeyTag -eq $sig.KeyTag -and $k.Algorithm -eq $sig.Algorithm -and
					($k.Flags -band 0x0100) -ne 0 -and ($k.Flags -band 0x0080) -eq 0 -and $k.Protocol -eq 3
				})
			if ($candidates.Count -eq 0)
			{
				$reasons.Add("No trusted DNSKEY for RRSIG key tag $($sig.KeyTag) algorithm $($sig.Algorithm)")
				continue
			}

			foreach ($candidate in $candidates)
			{
				try
				{
					$check = Test-DnssecRrsig -Rrsig $sig -Rrset $Rrset -DnskeyRrset @($candidate)
					# Test-DnssecRrsig returns an OBJECT (Valid/Reason); an object is always truthy, so the
					# .Valid property must be read - testing the object itself accepts every signature.
					$verdicts++
					if ($check.Valid)
					{
						return [pscustomobject]@{
							Valid       = $true
							Unsupported = $false
							Reason      = "RRSIG key tag $($sig.KeyTag) verified"
						}
					}
					$reasons.Add("RRSIG key tag $($sig.KeyTag): $($check.Reason)")
				}
				catch
				{
					Write-MyCatchAudit -Source 'Test-DnssecRrsetSignature: signature check threw (e.g. unsupported algorithm) - counted as a failed attempt, never as success' -ErrorRecord $_
					$reasons.Add("RRSIG key tag $($sig.KeyTag): $($_.Exception.Message)")
				}
			}
		}

		if ($considered -eq 0)
		{
			return [pscustomobject]@{
				Valid       = $false
				Unsupported = $false
				Reason      = "No RRSIG covers type $rrType at $ownerName"
			}
		}

		return [pscustomobject]@{
			Valid       = $false
			Unsupported = ($unsupported -gt 0 -and $verdicts -eq 0)
			Reason      = ($reasons -join '; ')
		}
	}
	catch
	{
		Write-MyCatchAudit -Source 'Test-DnssecRrsetSignature: unexpected error' -ErrorRecord $_
		return [pscustomobject]@{
			Valid       = $false
			Unsupported = $false
			Reason      = "Unexpected error verifying RRset: $($_.Exception.Message)"
		}
	}
}
