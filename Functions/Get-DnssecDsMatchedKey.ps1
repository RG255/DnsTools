function Get-DnssecDsMatchedKey
{
	<#
		.SYNOPSIS
		Returns the DNSKEY records of a zone that a DS RRset authenticates.

		.DESCRIPTION
		Added in 0.8. For each usable DS record (digest type 0 and unsupported digest types are skipped, never
		thrown), finds the DNSKEY whose key tag and algorithm match and whose digest over owner name + RDATA
		equals the DS digest. A candidate key must also be a zone key (flag 0x0100), have protocol 3, and not
		be revoked (flag 0x0080).

		Callers need the KEYS, not just a yes/no: the DNSKEY RRset must be signed by a key the parent's DS
		actually vouches for. Accepting a signature from ANY key in the (still unauthenticated) RRset lets an
		attacker add their own key next to the real public KSK and sign the forged set with it.

		.PARAMETER DsRecords
		The DS resource records (DnsResourceRecord) from the parent zone.

		.PARAMETER DnskeyRecords
		The DNSKEY resource records (DnsResourceRecord) of the child zone.

		.PARAMETER Zone
		The child zone name (owner name of the DNSKEY records).

		.OUTPUTS
		[DnsResourceRecord[]] - the matched DNSKEY records (possibly none).
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[AllowEmptyCollection()]
		[psobject[]]$DsRecords,

		[Parameter(Mandatory)]
		[AllowEmptyCollection()]
		[psobject[]]$DnskeyRecords,

		[Parameter(Mandatory)]
		[string]$Zone
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	try
	{
		$matched = New-Object -TypeName System.Collections.Generic.List[object]

		foreach ($dsRr in $DsRecords)
		{
			$ds = $dsRr.RDataObject
			if ($ds -isnot [DnsDsRecord])
			{continue}
			if ($ds.DigestType -eq 0)
			{continue}

			foreach ($keyRr in $DnskeyRecords)
			{
				$key = $keyRr.RDataObject
				if ($key -isnot [DnsDnskeyRecord])
				{continue}
				if ($key.KeyTag -ne $ds.KeyTag -or $key.Algorithm -ne $ds.Algorithm)
				{continue}
				if (($key.Flags -band 0x0100) -eq 0 -or ($key.Flags -band 0x0080) -ne 0 -or $key.Protocol -ne 3)
				{continue}

				try
				{$digest = Get-DnssecKeyDigest -OwnerName $Zone -Dnskey $key -DigestType $ds.DigestType}
				catch
				{
					# An unsupported digest type on ONE DS record must not stop the others from matching.
					Write-MyCatchAudit -Source 'Get-DnssecDsMatchedKey: digest computation failed for one DS record - skipping it, the other DS records may still match' -ErrorRecord $_
					continue
				}

				if ($digest -and [System.Linq.Enumerable]::SequenceEqual([byte[]]$digest, [byte[]]$ds.Digest))
				{
					if (-not $matched.Contains($keyRr))
					{$matched.Add($keyRr)}
				}
			}
		}

		return $matched.ToArray()
	}
	catch
	{
		Write-MyCatchAudit -Source 'Get-DnssecDsMatchedKey: unexpected error matching DS to DNSKEY' -ErrorRecord $_
		return @()
	}
}
