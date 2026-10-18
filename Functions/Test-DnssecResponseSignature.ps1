function Test-DnssecResponseSignature
{
	<#
		.SYNOPSIS
		Validates every RRset in a response's answer section against DNSSEC-authenticated keys.

		.DESCRIPTION
		Added in 0.8, replacing the validation that Resolve-DnsIterative -ValidateDnssec and Resolve-Dnssec each
		carried. For each RRset in the answers (grouped by owner name and type, RRSIGs excluded):

		- find the RRSIGs that cover it; none means the RRset is unsigned;
		- the RRSIG signer must be the owner name or an ancestor of it;
		- the signer's DNSKEY set must be authenticated all the way to a configured trust anchor
		  (Get-DnssecTrustedKey) - a DNSKEY fetched from the same untrusted resolution is NOT enough;
		- one RRSIG must verify against those keys (Test-DnssecRrsetSignature). Failures of OTHER RRSIGs on an RRset
		  that has one valid signature do not count against it (rollovers publish several);
		- a signature made with an algorithm this module cannot verify makes the RRset Insecure, not Bogus
		  (RFC 4035 section 5.2);
		- a wildcard-expanded answer (RRSIG Labels fewer than the owner's labels) additionally needs the signed
		  proof, from -Authority, that the exact name does not exist (RFC 4035 section 5.3.4).

		Status:
		  Secure         every RRset verified.
		  Insecure       no failure, but part of the answer is provably unsigned (or signed with an unsupported algorithm).
		  Bogus          an RRset carried a signature (or a chain link) that positively failed.
		  Indeterminate  nothing failed outright, but something could not be proven - the chain could not be
		                 completed, a wildcard proof was not available, or an RRset has no RRSIG in a zone not proven unsigned.
		  Unsigned       the response contains no RRSIG at all.

		.PARAMETER Answers
		The answer-section resource records (DnsResourceRecord), RRSIGs included.

		.PARAMETER Authority
		The authority-section records of the same response, used for the wildcard proof.

		.PARAMETER RootServers
		Root server addresses used for the DNSKEY/DS lookups.

		.OUTPUTS
		[PSCustomObject] with Status, Details (string[]), Chain (hashtable: signer zone -> DNSKEY records),
		DnskeyRecords and DsRecords (those of the first signer, for display).
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		[AllowEmptyCollection()]
		[psobject[]]$Answers,

		[AllowEmptyCollection()]
		[psobject[]]$Authority = @(),

		# Optional context for the CNAME-terminus check: when the answer is a CNAME chain, the final name must either have data of
		# the queried type or an authenticated denial. Supply the whole response (header + authority), the original query name and type.
		[object]$Response = $null,

		[string]$QueryName = '',

		[int]$QueryType = 0,

		[string[]]$RootServers = $script:RootServerAddresses
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	$details = New-Object -TypeName System.Collections.Generic.List[string]
	$chain = @{}

	try
	{
		$cache = @{}
		$rrsigs = @($Answers | Where-Object -FilterScript { $_.Type -eq 46 })
		if ($rrsigs.Count -eq 0)
		{
			$details.Add('No RRSIG records in response - response is not signed')
			$status = 'Unsigned'
			$firstOwner = @($Answers | Where-Object -FilterScript { $_.Type -ne 46 } | Select-Object -First 1)
			if ($firstOwner.Count -gt 0)
			{
				# Is that legitimate? Only if the chain of trust provably stops at an unsigned delegation.
				$proof = Get-DnssecInsecureProof -Name $firstOwner[0].Name -RootServers $RootServers -Cache $cache
				if ($proof.Status -eq 'Insecure')
				{$details.Add("Provably unsigned: zone '$($proof.Zone)' has an authenticated insecure delegation ($($proof.Reason))")}
				if ($proof.Status -eq 'Secure')
				{
					$status = 'Bogus'
					$details.Add("The zone is signed (chain authenticated to '$($proof.Zone)') but the answer has no RRSIG - signatures were stripped or withheld")
				}
				if ($proof.Status -eq 'Bogus')
				{
					$status = 'Bogus'
					$details.Add("Chain of trust broken at '$($proof.Zone)': $($proof.Reason)")
				}
				if ($proof.Status -eq 'Indeterminate')
				{$details.Add("Not proven whether the zone is legitimately unsigned: $($proof.Reason)")}
			}
			return [pscustomobject]@{
				Status        = $status
				Details       = $details.ToArray()
				Chain         = $chain
				DnskeyRecords = @()
				DsRecords     = @()
			}
		}

		$rrsets = @($Answers | Where-Object -FilterScript { $_.Type -ne 46 } |
				Group-Object -Property { '{0}|{1}' -f $_.Name.TrimEnd('.').ToLower(), $_.Type })

		$bogus = $false
		$indeterminate = $false
		$insecure = $false
		$firstSigner = $null

		foreach ($group in $rrsets)
		{
			$members = @($group.Group)
			$owner = $members[0].Name.TrimEnd('.').ToLower()
			$typeName = Format-DnsTypeName -Type $members[0].Type

			$covering = @($rrsigs | Where-Object -FilterScript {
					[int]$_.RDataObject.TypeCovered -eq [int]$members[0].Type -and $_.Name.TrimEnd('.').ToLower() -eq $owner
				})
			if ($covering.Count -eq 0)
			{
				# No RRSIG: legitimate only inside a provably unsigned zone (authenticated absence of DS).
				$proof = Get-DnssecInsecureProof -Name $owner -RootServers $RootServers -Cache $cache
				if ($proof.Status -eq 'Insecure')
				{
					$details.Add("RRset $owner $typeName is unsigned - provably insecure (zone '$($proof.Zone)')")
					$insecure = $true
				}
				if ($proof.Status -eq 'Secure')
				{
					$details.Add("RRset $owner $typeName has no RRSIG although its zone is signed - signature stripped or withheld")
					$bogus = $true
				}
				if ($proof.Status -eq 'Bogus')
				{
					$details.Add("RRset $owner $typeName has no RRSIG and the chain is broken at '$($proof.Zone)': $($proof.Reason)")
					$bogus = $true
				}
				if ($proof.Status -eq 'Indeterminate')
				{
					$details.Add("RRset $owner $typeName has no RRSIG and its zone is not proven unsigned: $($proof.Reason)")
					$indeterminate = $true
				}
				continue
			}

			# Outcome for THIS RRset only. A failure of one RRSIG must not poison an RRset that another RRSIG verifies
			# (algorithm / key rollovers publish several signatures).
			$secure = $false
			$secureSigner = $null
			$secureTrust = $null
			$secureSig = $null
			$rrBogus = $false
			$rrIndeterminate = $false
			$rrInsecure = $false
			$failure = $null

			foreach ($sigRr in $covering)
			{
				$signer = $sigRr.RDataObject.SignerName.TrimEnd('.').ToLower()
				$isAncestor = ($signer -eq '') -or ($owner -eq $signer) -or $owner.EndsWith('.' + $signer)
				if (-not $isAncestor)
				{
					$failure = "RRSIG signer '$signer' is not '$owner' or an ancestor of it"
					$rrBogus = $true
					continue
				}

				$trust = Get-DnssecTrustedKey -Zone $signer -RootServers $RootServers -Cache $cache
				if ($trust.Status -ne 'Secure')
				{
					$failure = "keys for '$signer' are not authenticated ($($trust.Status)): $($trust.Reason)"
					if ($trust.Status -eq 'Bogus')
					{$rrBogus = $true}
					if ($trust.Status -eq 'Insecure')
					{$rrInsecure = $true}
					if ($trust.Status -ne 'Bogus' -and $trust.Status -ne 'Insecure')
					{$rrIndeterminate = $true}
					continue
				}

				$check = Test-DnssecRrsetSignature -Rrset $members -Rrsigs @($sigRr) -KeyRecords $trust.Dnskeys -ZoneName $signer
				if ($check.Valid)
				{
					$secure = $true
					$secureSigner = $signer
					$secureTrust = $trust
					$secureSig = $sigRr.RDataObject
					break
				}

				$failure = "signature by '$signer' failed: $($check.Reason)"
				if ($check.Unsupported)
				{
					# RFC 4035 5.2: cannot verify with an algorithm we do not implement -> unsigned, not bogus.
					$rrInsecure = $true
					$failure = "signature algorithm not supported by this module - treated as unsigned (RFC 4035 5.2): $($check.Reason)"
				}
				if (-not $check.Unsupported)
				{$rrBogus = $true}
			}

			if ($secure)
			{
				$chain[$secureSigner] = $secureTrust.Dnskeys
				if ($null -eq $firstSigner)
				{$firstSigner = $secureTrust}

				# A wildcard-synthesised answer is only trustworthy with the signed proof that the exact name does not exist.
				# The RRSIG Labels field never counts a leading '*', so a signed RRset whose owner IS the wildcard (*.example.com,
				# queried directly) has Labels = labels - 1 yet is not an expansion.
				$ownerLabelList = @($owner.Split('.') | Where-Object -FilterScript { $_ -ne '' })
				$ownerLabelCount = $ownerLabelList.Count
				if ($ownerLabelCount -gt 0 -and $ownerLabelList[0] -eq '*')
				{$ownerLabelCount--}
				if ([int]$secureSig.Labels -lt $ownerLabelCount)
				{
					if (@($Authority).Count -eq 0)
					{
						$details.Add("RRset $owner $typeName : signature VALID, but it is wildcard-expanded and no authority section was supplied to prove the exact name does not exist")
						$indeterminate = $true
						continue
					}
					$wild = Test-DnssecWildcardProof -Owner $owner -LabelCount ([int]$secureSig.Labels) -Authority @($Authority) -Keys $secureTrust.Dnskeys -Zone $secureSigner
					if (-not $wild.Proven)
					{
						$details.Add("RRset $owner $typeName : NOT VALIDATED - wildcard-expanded answer without a valid proof that the name does not exist ($($wild.Reason))")
						$bogus = $true
						continue
					}
					$details.Add("RRset $owner $typeName : VALID (wildcard expansion proven: $($wild.Reason))")
					continue
				}

				$details.Add("RRset $owner $typeName : VALID")
				continue
			}

			$details.Add("RRset $owner $typeName : NOT VALIDATED - $failure")
			if ($rrBogus)
			{$bogus = $true}
			if (-not $rrBogus -and $rrInsecure)
			{$insecure = $true}
			if (-not $rrBogus -and -not $rrInsecure -and $rrIndeterminate)
			{$indeterminate = $true}
		}

		# CNAME terminus. Every RRset above verified, but a CNAME chain can be CUT SHORT: an on-path attacker who drops the records
		# after a signed CNAME leaves a perfectly valid-looking, truncated answer. Follow the chain from the query name; the name it
		# ends at must have data of the queried type, or an authenticated NODATA / NXDOMAIN for it.
		if ($null -ne $Response -and $QueryType -gt 0 -and $QueryType -ne 5 -and $QueryType -ne 255 -and $QueryName -ne '' -and -not $bogus)
		{
			$current = $QueryName.Trim().TrimEnd('.').ToLower()
			for ($hop = 0; $hop -lt 9; $hop++)
			{
				$link = @($Answers | Where-Object -FilterScript { $_.Type -eq 5 -and $_.Name.TrimEnd('.').ToLower() -eq $current } | Select-Object -First 1)
				if ($link.Count -eq 0)
				{break}
				$current = $link[0].RDataObject.Target.TrimEnd('.').ToLower()
			}
			$hasData = @($Answers | Where-Object -FilterScript { $_.Type -eq $QueryType -and $_.Name.TrimEnd('.').ToLower() -eq $current }).Count -gt 0
			if (-not $hasData)
			{
				$terminus = Test-DnssecNegativeResponse -Response $Response -QueryName $current -QueryType $QueryType -RootServers $RootServers -Cache $cache
				if ($terminus.Status -eq 'Secure')
				{$details.Add("The CNAME chain ends at '$current' with an authenticated $($terminus.Kind): $($terminus.Details -join '; ')")}
				if ($terminus.Status -ne 'Secure')
				{$details.Add("The answer ends at '$current' with no data of type $QueryType and no authenticated denial ($($terminus.Status)): $($terminus.Details -join '; ') - the chain may have been cut short")}
				if ($terminus.Status -eq 'Bogus')
				{$bogus = $true}
				if ($terminus.Status -eq 'Insecure')
				{$insecure = $true}
				if ($terminus.Status -eq 'Indeterminate')
				{$indeterminate = $true}
			}
		}

		$status = 'Secure'
		if ($insecure)
		{$status = 'Insecure'}
		if ($indeterminate)
		{$status = 'Indeterminate'}
		if ($bogus)
		{$status = 'Bogus'}

		return [pscustomobject]@{
			Status        = $status
			Details       = $details.ToArray()
			Chain         = $chain
			DnskeyRecords = if ($firstSigner)
			{@($firstSigner.Dnskeys)}
			else
			{@()}
			DsRecords     = if ($firstSigner)
			{@($firstSigner.DsRecords)}
			else
			{@()}
		}
	}
	catch
	{
		Write-MyCatchAudit -Source 'Test-DnssecResponseSignature: unexpected error validating the response' -ErrorRecord $_
		$details.Add("DNSSEC validation error: $($_.Exception.Message)")
		return [pscustomobject]@{
			Status        = 'Indeterminate'
			Details       = $details.ToArray()
			Chain         = $chain
			DnskeyRecords = @()
			DsRecords     = @()
		}
	}
}
