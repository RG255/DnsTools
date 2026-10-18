function Test-DnssecNegativeResponse
{
	<#
		.SYNOPSIS
		Validates an authenticated denial of existence: a signed NXDOMAIN or NODATA answer.

		.DESCRIPTION
		Added in 0.8. A negative answer carries no records to sign, so it is authenticated by the SOA plus NSEC or NSEC3
		records in the authority section, each signed by the zone. This checks, against the zone's authenticated keys
		(Get-DnssecTrustedKey):

		- the SOA RRset names the zone and is validly signed;
		- NODATA (RCODE 0): a record matching the query name exists and its type bitmap lacks the queried type and CNAME;
		- NXDOMAIN (RCODE 3), NSEC: one NSEC covers the query name and one covers (or no NSEC matches) the wildcard
		  at the closest encloser;
		- NXDOMAIN (RCODE 3), NSEC3 (RFC 5155 section 8.4): the closest encloser matches a record, the next closer name
		  is covered, and the wildcard at the closest encloser is covered;
		- every record used carries a valid RRSIG from the zone.

		Status:
		  Secure         the denial is authenticated.
		  Insecure       the zone is provably unsigned; the denial cannot be authenticated and is not an attack signal.
		  Bogus          a signature is bad, the denial records are missing from a signed zone, or the proof does not hold.
		  Indeterminate  the zone's keys could not be established, or the response shape is not one this handles
		                 (for example a wildcard-synthesised NODATA or an opt-out span).

		.PARAMETER Response
		The DnsPacket of the negative answer.

		.PARAMETER QueryName
		The name that was asked for.

		.PARAMETER QueryType
		The numeric record type that was asked for.

		.PARAMETER RootServers
		Root server addresses used to authenticate the zone's keys.

		.PARAMETER Cache
		Trust cache shared with Get-DnssecTrustedKey.

		.OUTPUTS
		[PSCustomObject] with Status, Kind (NXDOMAIN or NODATA) and Details (string[]).
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		$Response,

		[Parameter(Mandatory)]
		[string]$QueryName,

		[Parameter(Mandatory)]
		[int]$QueryType,

		[string[]]$RootServers = $script:RootServerAddresses,

		[hashtable]$Cache = @{}
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	$mk = { param($Status, $Kind, $Details) [pscustomobject]@{ Status = $Status; Kind = $Kind; Details = @($Details) } }
	$kind = 'NODATA'

	try
	{
		$rcode = [int]($Response.Header.Flags -band 0x000F)
		if ($rcode -eq 3)
		{$kind = 'NXDOMAIN'}
		if ($rcode -ne 3 -and $rcode -ne 0)
		{return & $mk 'Indeterminate' $kind "RCODE $rcode is not a negative answer this validates"}

		$qname = $QueryName.Trim().TrimEnd('.').ToLower()
		$authority = @($Response.Authority)
		$sigs = @($authority | Where-Object -FilterScript { $_.Type -eq 46 })

		$soa = @($authority | Where-Object -FilterScript { $_.Type -eq 6 })
		if ($soa.Count -eq 0)
		{return & $mk 'Indeterminate' $kind 'No SOA in the authority section'}
		$zone = $soa[0].Name.TrimEnd('.').ToLower()

		$trust = Get-DnssecTrustedKey -Zone $zone -RootServers $RootServers -Cache $Cache
		if ($trust.Status -ne 'Secure')
		{
			$mapped = $trust.Status
			return & $mk $mapped $kind "Zone '$zone' keys are not authenticated ($($trust.Status)): $($trust.Reason)"
		}

		$soaCheck = Test-DnssecRrsetSignature -Rrset $soa -Rrsigs $sigs -KeyRecords $trust.Dnskeys -ZoneName $zone
		if (-not $soaCheck.Valid)
		{return & $mk 'Bogus' $kind "SOA for '$zone' is not validly signed: $($soaCheck.Reason)"}

		$nsec = @($authority | Where-Object -FilterScript { $_.Type -eq 47 -and $_.RDataObject -is [DnsNsecRecord] })
		$nsec3 = @($authority | Where-Object -FilterScript { $_.Type -eq 50 -and $_.RDataObject -is [DnsNsec3Record] })
		if ($nsec.Count -eq 0 -and $nsec3.Count -eq 0)
		{return & $mk 'Bogus' $kind "Zone '$zone' is signed but the negative answer carries no NSEC/NSEC3 proof"}

		# Signature check for one denial record; remembers results so a record used twice is verified once.
		$verified = @{}
		$sigOk = {
			param($Rr)
			$key = '{0}|{1}' -f $Rr.Name.ToLower(), $Rr.Type
			if (-not $verified.ContainsKey($key))
			{
				$verified[$key] = (Test-DnssecRrsetSignature -Rrset @($Rr) -Rrsigs $sigs -KeyRecords $trust.Dnskeys -ZoneName $zone).Valid
			}
			return $verified[$key]
		}

		$typeBlocks = { param($Types) ($Types -contains $QueryType) -or ($Types -contains 5 -and $QueryType -ne 5) }

		# ------------------------------ NSEC ------------------------------
		if ($nsec.Count -gt 0)
		{
			$covers = {
				param($Rr, [string]$Name)
				$owner = $Rr.Name.TrimEnd('.').ToLower()
				$next = $Rr.RDataObject.NextDomainName.TrimEnd('.').ToLower()
				if ((Compare-DnsCanonicalName -A $owner -B $next) -lt 0)
				{return (Compare-DnsCanonicalName -A $owner -B $Name) -lt 0 -and (Compare-DnsCanonicalName -A $Name -B $next) -lt 0}
				return (Compare-DnsCanonicalName -A $Name -B $owner) -gt 0 -or (Compare-DnsCanonicalName -A $Name -B $next) -lt 0
			}

			if ($kind -eq 'NODATA')
			{
				$match = @($nsec | Where-Object -FilterScript { $_.Name.TrimEnd('.').ToLower() -eq $qname })
				if ($match.Count -eq 0)
				{return & $mk 'Indeterminate' $kind 'No NSEC matches the query name (a wildcard or empty-non-terminal NODATA is not handled)'}
				if (& $typeBlocks @($match[0].RDataObject.Types))
				{return & $mk 'Bogus' $kind "The NSEC at '$qname' lists the queried type (or a CNAME): the denial is false"}
				if (-not (& $sigOk $match[0]))
				{return & $mk 'Bogus' $kind "The NSEC at '$qname' is not validly signed by '$zone'"}
				return & $mk 'Secure' $kind "Signed NSEC at '$qname' proves no record of type $QueryType"
			}

			$cover = @($nsec | Where-Object -FilterScript { & $covers $_ $qname })
			if ($cover.Count -eq 0)
			{return & $mk 'Bogus' $kind "No NSEC covers '$qname'"}
			$owner = $cover[0].Name.TrimEnd('.').ToLower()
			$next = $cover[0].RDataObject.NextDomainName.TrimEnd('.').ToLower()

			# Closest encloser: the longest ancestor of the query name that is also an ancestor of the covering record's owner or next name.
			$ce = $zone
			$labels = @($qname.Split('.'))
			for ($i = 1; $i -lt $labels.Count; $i++)
			{
				$candidate = ($labels[$i..($labels.Count - 1)] -join '.')
				$ownerBelow = ($owner -eq $candidate) -or ($owner.EndsWith('.' + $candidate))
				$nextBelow = ($next -eq $candidate) -or ($next.EndsWith('.' + $candidate))
				if ($ownerBelow -or $nextBelow)
				{
					$ce = $candidate
					break
				}
			}
			$wildcard = '*.' + $ce
			if ($ce -eq '')
			{$wildcard = '*'}
			$wildMatch = @($nsec | Where-Object -FilterScript { $_.Name.TrimEnd('.').ToLower() -eq $wildcard })
			if ($wildMatch.Count -gt 0)
			{return & $mk 'Bogus' $kind "A wildcard '$wildcard' exists, so '$qname' cannot be NXDOMAIN"}
			$wildCover = @($nsec | Where-Object -FilterScript { & $covers $_ $wildcard })
			if ($wildCover.Count -eq 0)
			{return & $mk 'Bogus' $kind "No NSEC covers the wildcard '$wildcard' at the closest encloser '$ce'"}

			if (-not (& $sigOk $cover[0]) -or -not (& $sigOk $wildCover[0]))
			{return & $mk 'Bogus' $kind "An NSEC used in the NXDOMAIN proof is not validly signed by '$zone'"}
			return & $mk 'Secure' $kind "Signed NSEC records cover '$qname' and the wildcard at '$ce'"
		}

		# ------------------------------ NSEC3 ------------------------------
		$params = $nsec3[0].RDataObject
		$alg = [int]$params.HashAlgorithm
		$iter = [int]$params.Iterations
		[byte[]]$salt = @($params.Salt)
		if ($alg -ne 1)
		{return & $mk 'Indeterminate' $kind "NSEC3 hash algorithm $alg is not supported"}
		if ($iter -gt 2500)
		{return & $mk 'Indeterminate' $kind "NSEC3 iterations $iter exceed the 2500 limit"}

		$hashHex = {
			param([string]$Name)
			[BitConverter]::ToString((Get-DnssecNsec3Hash -name ($Name + '.') -Algorithm $alg -Iterations $iter -salt $salt))
		}
		$coversHash = {
			param($Rr, [string]$H)
			$a = [BitConverter]::ToString($Rr.RDataObject.OwnerHash)
			$b = [BitConverter]::ToString($Rr.RDataObject.NextHash)
			if ([string]::CompareOrdinal($a, $b) -lt 0)
			{return [string]::CompareOrdinal($a, $H) -lt 0 -and [string]::CompareOrdinal($H, $b) -lt 0}
			return [string]::CompareOrdinal($H, $a) -gt 0 -or [string]::CompareOrdinal($H, $b) -lt 0
		}
		$matchHash = {
			param([string]$H)
			@($nsec3 | Where-Object -FilterScript { [BitConverter]::ToString($_.RDataObject.OwnerHash) -eq $H })
		}

		if ($kind -eq 'NODATA')
		{
			$match = @(& $matchHash (& $hashHex $qname))
			if ($match.Count -eq 0)
			{return & $mk 'Indeterminate' $kind 'No NSEC3 matches the query name (an opt-out or wildcard NODATA is not handled)'}
			if (& $typeBlocks @($match[0].RDataObject.Types))
			{return & $mk 'Bogus' $kind "The NSEC3 for '$qname' lists the queried type (or a CNAME): the denial is false"}
			if (-not (& $sigOk $match[0]))
			{return & $mk 'Bogus' $kind "The NSEC3 for '$qname' is not validly signed by '$zone'"}
			return & $mk 'Secure' $kind "Signed NSEC3 for '$qname' proves no record of type $QueryType"
		}

		# NXDOMAIN: closest encloser proof (RFC 5155 section 8.4)
		$labels = @($qname.Split('.'))
		$ceName = $null
		$ceIndex = -1
		for ($i = 1; $i -lt $labels.Count; $i++)
		{
			$candidate = ($labels[$i..($labels.Count - 1)] -join '.')
			if (@(& $matchHash (& $hashHex $candidate)).Count -gt 0)
			{
				$ceName = $candidate
				$ceIndex = $i
				break
			}
		}
		if ($null -eq $ceName)
		{return & $mk 'Bogus' $kind "No NSEC3 matches any ancestor of '$qname' (no closest encloser)"}

		$nextCloser = ($labels[($ceIndex - 1)..($labels.Count - 1)] -join '.')
		$ncCover = @($nsec3 | Where-Object -FilterScript { & $coversHash $_ (& $hashHex $nextCloser) })
		if ($ncCover.Count -eq 0)
		{return & $mk 'Bogus' $kind "No NSEC3 covers the next closer name '$nextCloser'"}

		$wildcard = '*.' + $ceName
		$wHash = & $hashHex $wildcard
		if (@(& $matchHash $wHash).Count -gt 0)
		{return & $mk 'Bogus' $kind "A wildcard '$wildcard' exists, so '$qname' cannot be NXDOMAIN"}
		$wCover = @($nsec3 | Where-Object -FilterScript { & $coversHash $_ $wHash })
		if ($wCover.Count -eq 0)
		{return & $mk 'Bogus' $kind "No NSEC3 covers the wildcard '$wildcard' at the closest encloser '$ceName'"}

		$ceRr = @(& $matchHash (& $hashHex $ceName))
		if (-not (& $sigOk $ceRr[0]) -or -not (& $sigOk $ncCover[0]) -or -not (& $sigOk $wCover[0]))
		{return & $mk 'Bogus' $kind "An NSEC3 used in the NXDOMAIN proof is not validly signed by '$zone'"}

		return & $mk 'Secure' $kind "Signed NSEC3 closest-encloser proof for '$qname' (encloser '$ceName')"
	}
	catch
	{
		Write-MyCatchAudit -Source "Test-DnssecNegativeResponse: unexpected error validating the denial for '$QueryName'" -ErrorRecord $_
		return & $mk 'Indeterminate' $kind "Unexpected error: $($_.Exception.Message)"
	}
}
