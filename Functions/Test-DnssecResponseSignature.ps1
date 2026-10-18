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
		- one RRSIG must verify against those keys (Test-DnssecRrsetSignature).

		Status:
		  Secure         every RRset verified.
		  Bogus          an RRset carried a signature (or a chain link) that positively failed.
		  Indeterminate  nothing failed outright, but something could not be proven - the chain could not be
		                 completed, or an RRset has no RRSIG (an insecure delegation and a stripped signature
		                 cannot be told apart without a proof of non-existence of DS, which is not done here).
		  Unsigned       the response contains no RRSIG at all.

		.PARAMETER Answers
		The answer-section resource records (DnsResourceRecord), RRSIGs included.

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
				# 0.8: is that legitimate? Only if the chain of trust provably stops at an unsigned delegation.
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

			$secure = $false
			$failure = $null
			foreach ($sigRr in $covering)
			{
				$signer = $sigRr.RDataObject.SignerName.TrimEnd('.').ToLower()
				$isAncestor = ($signer -eq '') -or ($owner -eq $signer) -or $owner.EndsWith('.' + $signer)
				if (-not $isAncestor)
				{
					$failure = "RRSIG signer '$signer' is not '$owner' or an ancestor of it"
					$bogus = $true
					continue
				}

				$trust = Get-DnssecTrustedKey -Zone $signer -RootServers $RootServers -Cache $cache
				if ($trust.Status -ne 'Secure')
				{
					$failure = "keys for '$signer' are not authenticated ($($trust.Status)): $($trust.Reason)"
					if ($trust.Status -eq 'Bogus')
					{$bogus = $true}
					else
					{$indeterminate = $true}
					continue
				}

				$chain[$signer] = $trust.Dnskeys
				if ($null -eq $firstSigner)
				{$firstSigner = $trust}

				$check = Test-DnssecRrsetSignature -Rrset $members -Rrsigs @($sigRr) -KeyRecords $trust.Dnskeys -ZoneName $signer
				if ($check.Valid)
				{
					$secure = $true
					break
				}
				$failure = "signature by '$signer' failed: $($check.Reason)"
				$bogus = $true
			}

			if ($secure)
			{$details.Add("RRset $owner $typeName : VALID")}
			else
			{$details.Add("RRset $owner $typeName : NOT VALIDATED - $failure")}
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
