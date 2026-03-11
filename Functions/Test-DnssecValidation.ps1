function Test-DnssecValidation
{
	<#
	.SYNOPSIS
		Performs comprehensive DNSSEC validation with detailed reporting.

	.DESCRIPTION
		Validates the complete DNSSEC chain of trust for a domain name and generates a detailed report of all steps,
		findings, and any issues encountered during validation.

	.PARAMETER Name
		The fully qualified domain name to validate.

	.PARAMETER Type
		The DNS record type to query (default: 1 = A record).

	.PARAMETER RootServers
		Array of root server IP addresses to use for resolution (defaults to module-configured root servers).

	.EXAMPLE
		Test-DnssecValidation -Name cloudflare.com

	.EXAMPLE
		Test-DnssecValidation -Name www.dnssec-deployment.org -Type 1
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$Name,

		$Type = 'A',

		[Parameter(DontShow)]
		[string[]]$RootServers = $script:RootServerAddresses
	)

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	# Convert type name to code if needed
	$TypeCode = ConvertTo-DnsTypeCode -Type $Type
	$TypeDisplay = Format-DnsTypeName -Type $TypeCode

	$report = [System.Collections.ArrayList]::new()
	$issues = [System.Collections.ArrayList]::new()
	$startTime = Get-Date

	# Helper function to add report entries
	function Add-ReportEntry {
		param([string]$Section, [string]$Message, [string]$Level = 'INFO')
		$entry = [PSCustomObject]@{
			Timestamp = Get-Date
			Section   = $Section
			Level     = $Level
			Message   = $Message
		}
		[void]$report.Add($entry)

		$levelColor = switch ($Level) {
			'SUCCESS' { 'Green' }
			'ERROR'   { 'Red' }
			'WARNING' { 'Yellow' }
			default   { 'Cyan' }
		}
		Write-Host "[$Level] $Section - $Message" -ForegroundColor $levelColor
	}

	# Helper function to format hex strings
	function Format-HexString {
		param([byte[]]$bytes, [int]$maxLength = 32)
		if (-not $bytes) { return 'null' }
		$hex = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
		if ($hex.Length -gt $maxLength) {
			return $hex.Substring(0, $maxLength) + "... ($($bytes.Length) bytes)"
		}
		return $hex
	}

	Add-ReportEntry -Section 'INITIALIZATION' -Message "Starting DNSSEC validation for: $Name (Type: $TypeDisplay)"
	Add-ReportEntry -Section 'INITIALIZATION' -Message "Using $($RootServers.Count) root servers"

	# Initialize trust anchors
	try {
		Initialize-DnssecTrustAnchors
		Add-ReportEntry -Section 'INITIALIZATION' -Level 'SUCCESS' -Message 'Trust anchors initialized'
	}
	catch {
		Add-ReportEntry -Section 'INITIALIZATION' -Level 'WARNING' -Message "Trust anchor initialization failed: $($_.Exception.Message)"
	}

	# Step 1: Check trust anchors
	Add-ReportEntry -Section 'TRUST ANCHORS' -Message 'Checking configured trust anchors'
	$trustAnchors = @(Get-DnssecTrustAnchors)
	if ($trustAnchors -and $trustAnchors.Count -gt 0) {
		foreach ($anchor in $trustAnchors) {
			Add-ReportEntry -Section 'TRUST ANCHORS' -Message "Zone: $($anchor.Zone), KeyTag: $($anchor.KeyTag), Algorithm: $($anchor.Algorithm), DigestType: $($anchor.DigestType)"
		}
		Add-ReportEntry -Section 'TRUST ANCHORS' -Level 'SUCCESS' -Message "Found $($trustAnchors.Count) trust anchor(s)"
	}
	else {
		Add-ReportEntry -Section 'TRUST ANCHORS' -Level 'ERROR' -Message 'No trust anchors configured'
		[void]$issues.Add('No trust anchors found - DNSSEC validation cannot proceed')
	}

	# Step 2: Build zone path
	$fqdn = $Name.TrimEnd('.').ToLower()
	$labels = $fqdn.Split('.')
	$zones = @('.')
	for ($i = $labels.Count - 1; $i -ge 0; $i--) {
		$zoneName = ($labels[$i..($labels.Count - 1)] -join '.') + '.'
		$zones += $zoneName
	}

	Add-ReportEntry -Section 'ZONE PATH' -Message "DNSSEC validation path: $($zones -join ' -> ')"

	# Step 3: Validate each zone in the chain
	$validatedZones = @{}

	# Root is trusted
	$validatedZones['.'] = @{
		Zone     = '.'
		Status   = 'TRUSTED'
		Reason   = 'Trust anchor'
		Verified = $true
	}
	Add-ReportEntry -Section 'ZONE VALIDATION' -Level 'SUCCESS' -Message "Root zone (.) is trusted via trust anchor"

	# Validate each child zone
	for ($i = 1; $i -lt $zones.Count; $i++) {
		$childZone = $zones[$i]
		$parentZone = $zones[$i - 1]

		Add-ReportEntry -Section 'ZONE VALIDATION' -Message "========================================"
		Add-ReportEntry -Section 'ZONE VALIDATION' -Message "Validating zone: $childZone (parent: $parentZone)"

		try {
			# Query for DS records in parent zone
			Add-ReportEntry -Section 'DS QUERY' -Message "Querying DS records for $childZone from parent zone $parentZone"
			$dsResult = Resolve-DnsIterative -name $childZone -type 43 -RootServers $RootServers

			if ($dsResult.Status -ne 'Final') {
				Add-ReportEntry -Section 'DS QUERY' -Level 'WARNING' -Message "DS query failed: $($dsResult.Reason)"
				[void]$issues.Add("No DS records found for $childZone - zone may not be signed")
				$validatedZones[$childZone] = @{
					Zone     = $childZone
					Status   = 'UNSIGNED'
					Reason   = 'No DS records found'
					Verified = $false
				}
				continue
			}

			$dsRecords = @($dsResult.Response.Answers | Where-Object { $_.Type -eq 43 })
			Add-ReportEntry -Section 'DS QUERY' -Level 'SUCCESS' -Message "Found $($dsRecords.Count) DS record(s)"

			foreach ($ds in $dsRecords) {
				$dsData = $ds.RDataObject
				Add-ReportEntry -Section 'DS DETAILS' -Message "DS: KeyTag=$($dsData.KeyTag), Algorithm=$($dsData.Algorithm), DigestType=$($dsData.DigestType), Digest=$(Format-HexString $dsData.Digest)"
			}

			# Query for DNSKEY records in child zone
			Add-ReportEntry -Section 'DNSKEY QUERY' -Message "Querying DNSKEY records for $childZone"
			$dnskeyResult = Resolve-DnsIterative -name $childZone -type 48 -RootServers $RootServers

			if ($dnskeyResult.Status -ne 'Final') {
				Add-ReportEntry -Section 'DNSKEY QUERY' -Level 'ERROR' -Message "DNSKEY query failed: $($dnskeyResult.Reason)"
				[void]$issues.Add("Failed to retrieve DNSKEY for $childZone")
				$validatedZones[$childZone] = @{
					Zone     = $childZone
					Status   = 'BOGUS'
					Reason   = 'DNSKEY query failed'
					Verified = $false
				}
				continue
			}

			$dnskeyRecords = @($dnskeyResult.Response.Answers | Where-Object { $_.Type -eq 48 })
			$rrsigRecords = @($dnskeyResult.Response.Answers | Where-Object { $_.Type -eq 46 })

			Add-ReportEntry -Section 'DNSKEY QUERY' -Level 'SUCCESS' -Message "Found $($dnskeyRecords.Count) DNSKEY record(s) and $($rrsigRecords.Count) RRSIG record(s)"

			foreach ($dnskey in $dnskeyRecords) {
				$dnskeyData = $dnskey.RDataObject
				$keyType = if (($dnskeyData.Flags -band 0x0001) -ne 0) { 'SEP (Zone Signing Key)' } else { 'ZSK (Zone Signing Key)' }
				Add-ReportEntry -Section 'DNSKEY DETAILS' -Message "DNSKEY: Flags=$($dnskeyData.Flags) ($keyType), Protocol=$($dnskeyData.Protocol), Algorithm=$($dnskeyData.Algorithm), KeyTag=$($dnskeyData.KeyTag)"
			}

			# Validate DS -> DNSKEY matching
			Add-ReportEntry -Section 'DS-DNSKEY VALIDATION' -Message "Validating DS records match DNSKEY records"
			$dsValidation = Test-DnssecDsForDnskey -DsRrset $dsRecords -DnskeyRrset $dnskeyRecords -ChildZoneName $childZone

			$matchedDs = @($dsValidation | Where-Object { $_.Valid })
			if ($matchedDs -and $matchedDs.Count -gt 0) {
				Add-ReportEntry -Section 'DS-DNSKEY VALIDATION' -Level 'SUCCESS' -Message "$($matchedDs.Count) DS record(s) successfully matched to DNSKEY"
				foreach ($match in $matchedDs) {
					Add-ReportEntry -Section 'DS-DNSKEY VALIDATION' -Message "Matched: DS KeyTag=$($match.DsRecord.KeyTag)"
				}
			}
			else {
				Add-ReportEntry -Section 'DS-DNSKEY VALIDATION' -Level 'ERROR' -Message 'No DS records matched any DNSKEY'
				[void]$issues.Add("DS-DNSKEY validation failed for $childZone")
				$validatedZones[$childZone] = @{
					Zone     = $childZone
					Status   = 'BOGUS'
					Reason   = 'DS-DNSKEY mismatch'
					Verified = $false
				}
				continue
			}

			# Validate RRSIG signatures on DNSKEY RRset
			if ($rrsigRecords) {
				Add-ReportEntry -Section 'RRSIG VALIDATION' -Message "Validating RRSIG signatures on DNSKEY RRset"

				$validSigs = 0
				foreach ($rrsig in $rrsigRecords) {
					$rrsigData = $rrsig.RDataObject

					# Check time window
					$timeValid = Test-DnssecTimeWindow -Rrsig $rrsigData
					if (-not $timeValid) {
						Add-ReportEntry -Section 'RRSIG VALIDATION' -Level 'WARNING' -Message "RRSIG KeyTag=$($rrsigData.KeyTag) is outside validity window (Inception: $($rrsigData.Inception), Expiration: $($rrsigData.Expiration))"
						continue
					}

					Add-ReportEntry -Section 'RRSIG VALIDATION' -Message "RRSIG: KeyTag=$($rrsigData.KeyTag), Algorithm=$($rrsigData.Algorithm), TypeCovered=$($rrsigData.TypeCovered), SignerName=$($rrsigData.SignerName)"

					# Find matching DNSKEY
					$signingKey = Get-DnssecSigningKey -Rrsig $rrsigData -DnskeyRrset $dnskeyRecords
					if (-not $signingKey) {
						Add-ReportEntry -Section 'RRSIG VALIDATION' -Level 'WARNING' -Message "No matching DNSKEY found for RRSIG KeyTag=$($rrsigData.KeyTag)"
						continue
					}

					# Verify signature
					$signedData = Get-DnssecSignedData -Rrsig $rrsigData -Rrset $dnskeyRecords
			$sigValid = Test-DnssecSignature -SignedData $signedData -Rrsig $rrsigData -Dnskey $signingKey.RDataObject
					if ($sigValid) {
						Add-ReportEntry -Section 'RRSIG VALIDATION' -Level 'SUCCESS' -Message "Signature valid for RRSIG KeyTag=$($rrsigData.KeyTag)"
						$validSigs++
					}
					else {
						Add-ReportEntry -Section 'RRSIG VALIDATION' -Level 'WARNING' -Message "Signature verification FAILED for RRSIG KeyTag=$($rrsigData.KeyTag)"
					}
				}

				if ($validSigs -gt 0) {
					Add-ReportEntry -Section 'RRSIG VALIDATION' -Level 'SUCCESS' -Message "$validSigs valid signature(s) found"
				}
				else {
					Add-ReportEntry -Section 'RRSIG VALIDATION' -Level 'ERROR' -Message 'No valid signatures found'
					[void]$issues.Add("RRSIG validation failed for $childZone")
					$validatedZones[$childZone] = @{
						Zone     = $childZone
						Status   = 'BOGUS'
						Reason   = 'No valid signatures'
						Verified = $false
					}
					continue
				}
			}
			else {
				Add-ReportEntry -Section 'RRSIG VALIDATION' -Level 'ERROR' -Message 'No RRSIG records found'
				[void]$issues.Add("No RRSIG records for $childZone")
			}

			$validatedZones[$childZone] = @{
				Zone     = $childZone
				Status   = 'SECURE'
				Reason   = 'Full chain validated'
				Verified = $true
			}
			Add-ReportEntry -Section 'ZONE VALIDATION' -Level 'SUCCESS' -Message "Zone $childZone is SECURE"

		}
		catch {
			Add-ReportEntry -Section 'ZONE VALIDATION' -Level 'ERROR' -Message "Exception during validation: $($_.Exception.Message)"
			[void]$issues.Add("Exception validating $childZone : $($_.Exception.Message)")
			$validatedZones[$childZone] = @{
				Zone     = $childZone
				Status   = 'ERROR'
				Reason   = $_.Exception.Message
				Verified = $false
			}
		}
	}

	# Step 4: Validate the actual target record
	Add-ReportEntry -Section 'TARGET VALIDATION' -Message "========================================"
	Add-ReportEntry -Section 'TARGET VALIDATION' -Message "Validating target record: $Name (Type: $TypeDisplay)"

	try {
		$targetResult = Resolve-Dnssec -name $Name -type $TypeCode -RootServers $RootServers

		if ($targetResult.Valid) {
			Add-ReportEntry -Section 'TARGET VALIDATION' -Level 'SUCCESS' -Message "Target record validation: SECURE"
			Add-ReportEntry -Section 'TARGET VALIDATION' -Message "Reason: $($targetResult.Reason)"

			if ($targetResult.Answer) {
				Add-ReportEntry -Section 'TARGET VALIDATION' -Message "Answer records found: $(@($targetResult.Answer).Count)"
				foreach ($answer in $targetResult.Answer) {
					$rdataInfo = if ($answer.RDataObject) { $answer.RDataObject.ToString() } else { "" }
					Add-ReportEntry -Section 'TARGET VALIDATION' -Message "  $($answer.Name) TTL=$($answer.Ttl) Type=$($answer.Type) $rdataInfo"
				}
			}
		}
		else {
			Add-ReportEntry -Section 'TARGET VALIDATION' -Level 'ERROR' -Message "Target record validation: BOGUS"
			Add-ReportEntry -Section 'TARGET VALIDATION' -Message "Reason: $($targetResult.Reason)"
			[void]$issues.Add("Target record validation failed: $($targetResult.Reason)")
		}
	}
	catch {
		Add-ReportEntry -Section 'TARGET VALIDATION' -Level 'ERROR' -Message "Exception: $($_.Exception.Message)"
		[void]$issues.Add("Target validation exception: $($_.Exception.Message)")
	}

	# Generate summary
	$endTime = Get-Date
	$duration = $endTime - $startTime

	Add-ReportEntry -Section 'SUMMARY' -Message "========================================"
	Add-ReportEntry -Section 'SUMMARY' -Message "DNSSEC Validation Summary for: $Name"
	Add-ReportEntry -Section 'SUMMARY' -Message "Validation completed in: $($duration.TotalSeconds) seconds"
	Add-ReportEntry -Section 'SUMMARY' -Message "Total zones in chain: $($zones.Count)"

	$secureZones = @($validatedZones.Values | Where-Object { $_.Status -eq 'SECURE' -or $_.Status -eq 'TRUSTED' }).Count
	$bogusZones = @($validatedZones.Values | Where-Object { $_.Status -eq 'BOGUS' -or $_.Status -eq 'ERROR' }).Count
	$unsignedZones = @($validatedZones.Values | Where-Object { $_.Status -eq 'UNSIGNED' }).Count

	Add-ReportEntry -Section 'SUMMARY' -Message "Secure zones: $secureZones"
	Add-ReportEntry -Section 'SUMMARY' -Message "Bogus zones: $bogusZones"
	Add-ReportEntry -Section 'SUMMARY' -Message "Unsigned zones: $unsignedZones"

	if ($issues.Count -gt 0) {
		Add-ReportEntry -Section 'SUMMARY' -Level 'WARNING' -Message "Issues found: $($issues.Count)"
		foreach ($issue in $issues) {
			Add-ReportEntry -Section 'ISSUES' -Level 'WARNING' -Message $issue
		}
	}
	else {
		Add-ReportEntry -Section 'SUMMARY' -Level 'SUCCESS' -Message "No issues found - DNSSEC is correctly implemented"
	}

	# Final verdict
	$allSecure = ($bogusZones -eq 0) -and ($validatedZones[$zones[-1]].Verified -eq $true)
	if ($allSecure) {
		Add-ReportEntry -Section 'VERDICT' -Level 'SUCCESS' -Message "DNSSEC VALIDATION: PASSED - Chain of trust is intact"
	}
	else {
		Add-ReportEntry -Section 'VERDICT' -Level 'ERROR' -Message "DNSSEC VALIDATION: FAILED - Chain of trust is broken"
	}

	# Helper function to get type name
	function Get-TypeName {
		param([int]$typeNum)
		$typeMap = @{
			1 = 'A'; 2 = 'NS'; 5 = 'CNAME'; 6 = 'SOA'; 15 = 'MX'; 16 = 'TXT'
			28 = 'AAAA'; 43 = 'DS'; 46 = 'RRSIG'; 48 = 'DNSKEY'; 50 = 'NSEC3'
		}
		if ($typeMap.ContainsKey($typeNum)) { return $typeMap[$typeNum] }
		return "TYPE$typeNum"
	}

	# Helper function to format answer data
	function Format-AnswerData {
		param($answer)
		if (-not $answer.RDataObject) { return '' }
		$rdata = $answer.RDataObject

		switch ($answer.Type) {
			1 { return $rdata.Address }
			28 { return $rdata.Address }
			2 { return $rdata.NsName }
			5 { return $rdata.CName }
			15 { return "$($rdata.Preference) $($rdata.Exchange)" }
			default { return '[Complex RDATA]' }
		}
	}

	# Return the report and validation result
	return [PSCustomObject]@{
		Name           = $Name
		Type           = $TypeDisplay
		TypeCode       = $TypeCode
		ValidationTime = $duration
		Passed         = $allSecure
		ZonesValidated = $validatedZones
		Issues         = $issues
		Report         = $report
	}
}
