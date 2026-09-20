function Format-DnsIterativeResult
{
	<#
    .SYNOPSIS
        Formats the raw result from Resolve-DnsIterative into a user-friendly object.

    .DESCRIPTION
        Takes the internal result object from Resolve-DnsIterative (with Status, Response, Reason)
        and converts it to a user-friendly format suitable for interactive use.

    .PARAMETER Result
        The raw result object from Resolve-DnsIterative.

    .PARAMETER QueryName
        The original query name (for display purposes).

    .PARAMETER QueryType
        The original query type (for display purposes).

    .EXAMPLE
        $raw = Resolve-DnsIterative -Name "example.com" -Type A -Raw
        Format-DnsIterativeResult -Result $raw -QueryName "example.com" -QueryType "A(1)"
    #>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory, ValueFromPipeline)]
		[PSCustomObject]$Result,

		[Parameter(Mandatory)]
		[string]$QueryName,

		[Parameter(Mandatory)]
		[string]$QueryType
	)

	begin {
		If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }
	}

	process {
		if ($Result.Status -eq 'Final' -and $Result.Response) {
			# Successful resolution - format the answers
			$answers = @()

			if ($Result.Response.Answers -and $Result.Response.Answers.Count -gt 0) {
				foreach ($record in $Result.Response.Answers) {
					$answers += Format-DnsRecord -Record $record -Section 'Answer'
				}
			}

			$authority = @()
			if ($Result.Response.Authority -and $Result.Response.Authority.Count -gt 0) {
				foreach ($record in $Result.Response.Authority) {
					$authority += Format-DnsRecord -Record $record -Section 'Authority'
				}
			}

			$additional = @()
			if ($Result.Response.Additional -and $Result.Response.Additional.Count -gt 0) {
				foreach ($record in $Result.Response.Additional) {
					# Skip OPT records from additional section display
					if ($record.Type -ne 41) {
						$additional += Format-DnsRecord -Record $record -Section 'Additional'
					}
				}
			}

			# Extract server from Reason
			$server = $Result.Reason -replace 'Answer found from ', ''

			# Decode header flags
			$headerFlags = $Result.Response.Header.Flags
			$flagList = @()
			if ($headerFlags -band 0x8000) { $flagList += 'QR' }      # Query/Response
			if ($headerFlags -band 0x0400) { $flagList += 'AA' }      # Authoritative Answer
			if ($headerFlags -band 0x0200) { $flagList += 'TC' }      # Truncated
			if ($headerFlags -band 0x0100) { $flagList += 'RD' }      # Recursion Desired
			if ($headerFlags -band 0x0080) { $flagList += 'RA' }      # Recursion Available
			if ($headerFlags -band 0x0020) { $flagList += 'AD' }      # Authenticated Data (DNSSEC)
			if ($headerFlags -band 0x0010) { $flagList += 'CD' }      # Checking Disabled (DNSSEC)

			# Extract OpCode (bits 11-14)
			$opCode = ($headerFlags -shr 11) -band 0x0F
			$opCodeName = switch ($opCode) {
				0 { 'QUERY' }
				1 { 'IQUERY' }
				2 { 'STATUS' }
				4 { 'NOTIFY' }
				5 { 'UPDATE' }
				default { "OPCODE$opCode" }
			}

			# Extract RCode (bits 0-3 of second byte)
			$rCode = $headerFlags -band 0x000F
			$rCodeName = switch ($rCode) {
				0 { 'NOERROR' }
				1 { 'FORMERR' }
				2 { 'SERVFAIL' }
				3 { 'NXDOMAIN' }
				4 { 'NOTIMP' }
				5 { 'REFUSED' }
				6 { 'YXDOMAIN' }
				7 { 'YXRRSET' }
				8 { 'NXRRSET' }
				9 { 'NOTAUTH' }
				10 { 'NOTZONE' }
				default { 'RCODE' }
			}
			$rCodeFormatted = "$rCodeName($rCode)"

			$flagsFormatted = "0x{0:X4} ({1})" -f $headerFlags, ($flagList -join ', ')

			# Extract EDNS/OPT information if present
			$ednsInfo = $null
			$optRecord = $Result.Response.Additional | Where-Object { $_.Type -eq 41 } | Select-Object -First 1
			if ($optRecord -and $optRecord.RDataObject) {
				$opt = $optRecord.RDataObject
				$ednsFlags = @()
				if ($opt.Flags -band 0x8000) { $ednsFlags += 'DO' }  # DNSSEC OK
				$ednsFlagsStr = if ($ednsFlags.Count -gt 0) { $ednsFlags -join ', ' } else { 'None' }
				$ednsInfo = [PSCustomObject]@{
					Version        = $opt.Version
					UdpPayloadSize = $opt.UdpPayloadSize
					Flags          = "0x{0:X4} ({1})" -f $opt.Flags, $ednsFlagsStr
					ExtendedRCode  = $opt.ExtendedRcode
				}
			}

			$result = [PSCustomObject]@{
				QueryName       = $QueryName
				QueryType       = $QueryType
				Status          = 'Success'
				Server          = $server
				Flags           = $flagsFormatted
				OpCode          = $opCodeName
				RCode           = $rCodeFormatted
				AnswerCount     = $Result.Response.Answers.Count
				Answers         = $answers
				AuthorityCount  = $Result.Response.Authority.Count
				Authority       = $authority
				AdditionalCount = ($additional | Measure-Object).Count
				Additional      = $additional
			}

			# Add EDNS info if present
			if ($ednsInfo) {
				$result | Add-Member -NotePropertyName 'EDNS' -NotePropertyValue $ednsInfo -Force
			}

			return $result
		}
		else {
			# Failed or bailed out
			return [PSCustomObject]@{
				QueryName = $QueryName
				QueryType = $QueryType
				Status    = $Result.Status
				Message   = $Result.Reason
			}
		}
	}
}

function Format-DnsRecord
{
	<#
    .SYNOPSIS
        Formats a single DNS resource record for display.

    .DESCRIPTION
        Converts a DnsResourceRecord object into a user-friendly PSCustomObject
        with type-specific properties extracted from RDataObject.

    .PARAMETER Record
        The DNS resource record to format.

    .PARAMETER Section
        The section this record came from (Answer, Authority, Additional).
    #>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		$Record,

		[Parameter(Mandatory)]
		[ValidateSet('Answer', 'Authority', 'Additional')]
		[string]$Section
	)

	# Deliberately NOT traced (2026-09-15): called once per DNS record inside Format-DnsIterativeResult's
	# own loop (up to dozens of times per single query) - Format-DnsIterativeResult's own trace stamp
	# already establishes the operation happened; tracing every record adds volume with no extra
	# diagnostic value. Same "per-item/stream-processing helper" exemption the trace facility's own plan
	# documents for DnsBinaryReader's per-byte read methods - see
	# _PlanningDocs\_Repo\2026-09-13_Function-Trace-Facility-Plan.md, "What gets instrumented".
	$typeName = Format-DnsTypeName -Type $Record.Type
	$rdata = $Record.RDataObject

	# Build base properties
	$props = [ordered]@{
		Name    = $Record.Name
		Type    = $typeName
		TTL     = $Record.Ttl
		Section = $Section
	}

	# Add type-specific data
	switch ($Record.Type) {
		1 {  # A
			if ($rdata -and $rdata.Address) {
				$props['Address'] = $rdata.Address
			}
		}
		28 { # AAAA
			if ($rdata -and $rdata.Address) {
				$props['Address'] = $rdata.Address
			}
		}
		2 {  # NS
			if ($rdata -and $rdata.NsName) {
				$props['NameServer'] = $rdata.NsName
			}
		}
		5 {  # CNAME
			if ($rdata -and $rdata.Target) {
				$props['CanonicalName'] = $rdata.Target
			}
		}
		6 {  # SOA
			if ($rdata) {
				$props['MName'] = $rdata.MName
				$props['RName'] = $rdata.RName
				$props['Serial'] = $rdata.Serial
				$props['Refresh'] = $rdata.Refresh
				$props['Retry'] = $rdata.Retry
				$props['Expire'] = $rdata.Expire
				$props['Minimum'] = $rdata.Minimum
			}
		}
		12 { # PTR
			if ($rdata -and $rdata.Pointer) {
				$props['PtrName'] = $rdata.Pointer
			}
		}
		15 { # MX
			if ($rdata) {
				$props['Priority'] = "Priority($($rdata.Preference))"
				$props['Exchange'] = $rdata.Exchange
			}
		}
		16 { # TXT
			if ($rdata -and $rdata.Strings) {
				$props['Text'] = $rdata.Strings -join ''
			}
		}
		35 { # NAPTR
			if ($rdata) {
				$props['Order'] = $rdata.Order
				$props['Preference'] = $rdata.Preference
				$props['Flags'] = $rdata.Flags
				$props['Services'] = $rdata.Services
				$props['Regexp'] = $rdata.Regexp
				$props['Replacement'] = $rdata.Replacement
			}
		}
		39 { # DNAME
			if ($rdata -and $rdata.Target) {
				$props['Target'] = $rdata.Target
			}
		}
		44 { # SSHFP
			if ($rdata) {
				$sshAlgName = if ($script:SshfpAlgorithmMap.ContainsKey([int]$rdata.Algorithm)) {
					$script:SshfpAlgorithmMap[[int]$rdata.Algorithm]
				} else { 'Unknown' }
				$props['Algorithm'] = "$sshAlgName($($rdata.Algorithm))"
				$sshFpName = if ($script:SshfpFingerprintTypeMap.ContainsKey([int]$rdata.FingerprintType)) {
					$script:SshfpFingerprintTypeMap[[int]$rdata.FingerprintType]
				} else { 'Unknown' }
				$props['FingerprintType'] = "$sshFpName($($rdata.FingerprintType))"
				$props['Fingerprint'] = $rdata.GetFingerprintHex()
			}
		}
		52 { # TLSA
			if ($rdata) {
				$usageName = if ($script:TlsaUsageMap.ContainsKey([int]$rdata.CertUsage)) {
					$script:TlsaUsageMap[[int]$rdata.CertUsage]
				} else { 'Unknown' }
				$props['CertUsage'] = "$usageName($($rdata.CertUsage))"
				$selectorName = if ($script:TlsaSelectorMap.ContainsKey([int]$rdata.Selector)) {
					$script:TlsaSelectorMap[[int]$rdata.Selector]
				} else { 'Unknown' }
				$props['Selector'] = "$selectorName($($rdata.Selector))"
				$matchingName = if ($script:TlsaMatchingTypeMap.ContainsKey([int]$rdata.MatchingType)) {
					$script:TlsaMatchingTypeMap[[int]$rdata.MatchingType]
				} else { 'Unknown' }
				$props['MatchingType'] = "$matchingName($($rdata.MatchingType))"
				$props['CertificateData'] = ($rdata.CertificateData | ForEach-Object { $_.ToString('x2') }) -join ''
			}
		}
		17 { # RP
			if ($rdata) {
				$props['MailBox'] = $rdata.MailBox
				$props['TxtDomain'] = $rdata.TxtDomain
			}
		}
		45 { # IPSECKEY
			if ($rdata) {
				$props['Precedence'] = $rdata.Precedence
				$gwTypeName = switch ($rdata.GatewayType) {
					0 { 'None' }
					1 { 'IPv4' }
					2 { 'IPv6' }
					3 { 'DomainName' }
					default { 'Unknown' }
				}
				$props['GatewayType'] = "$gwTypeName($($rdata.GatewayType))"
				$props['Gateway'] = $rdata.Gateway
				$ipsecAlgName = switch ($rdata.Algorithm) {
					0 { 'None' }
					1 { 'DSA' }
					2 { 'RSA' }
					3 { 'ECDSA' }
					default { 'Unknown' }
				}
				$props['Algorithm'] = "$ipsecAlgName($($rdata.Algorithm))"
				$props['PublicKey'] = [Convert]::ToBase64String($rdata.PublicKey)
			}
		}
		61 { # OPENPGPKEY
			if ($rdata) {
				$props['PublicKey'] = [Convert]::ToBase64String($rdata.PublicKey)
			}
		}
		33 { # SRV
			if ($rdata) {
				$props['Priority'] = $rdata.Priority
				$props['Weight'] = $rdata.Weight
				$props['Port'] = $rdata.Port
				$props['Target'] = $rdata.Target
			}
		}
		43 { # DS
			if ($rdata) {
				$props['KeyTag'] = $rdata.KeyTag
				$props['Algorithm'] = Format-DnssecAlgorithmName -Algorithm $rdata.Algorithm
				$digestName = switch ($rdata.DigestType) {
					1 { 'SHA-1' }
					2 { 'SHA-256' }
					4 { 'SHA-384' }
					default { "Unknown($($rdata.DigestType))" }
				}
				$props['DigestType'] = "$digestName($($rdata.DigestType))"
				$props['Digest'] = $rdata.GetDigestHex()
			}
		}
		46 { # RRSIG
			if ($rdata) {
				$props['TypeCovered'] = Format-DnsTypeName -Type $rdata.TypeCovered
				$props['Algorithm'] = Format-DnssecAlgorithmName -Algorithm $rdata.Algorithm
				$props['Labels'] = $rdata.Labels
				$props['OriginalTtl'] = $rdata.OriginalTtl
				$props['KeyTag'] = $rdata.KeyTag
				$props['SignerName'] = $rdata.SignerName
				# Convert Unix timestamps to readable dates
				$epoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
				$props['Expiration'] = $epoch.AddSeconds($rdata.Expiration).ToString('yyyy-MM-dd HH:mm:ss UTC')
				$props['Inception'] = $epoch.AddSeconds($rdata.Inception).ToString('yyyy-MM-dd HH:mm:ss UTC')
			}
		}
		47 { # NSEC
			if ($rdata) {
				$props['NextName'] = $rdata.NextName
				$props['TypeBitMaps'] = ($rdata.TypeBitMaps | ForEach-Object { Format-DnsTypeName -Type $_ }) -join ', '
			}
		}
		48 { # DNSKEY
			if ($rdata) {
				# Decode DNSKEY flags
				$flagList = @()
				if ($rdata.Flags -band 0x0100) { $flagList += 'ZONE' }
				if ($rdata.Flags -band 0x0080) { $flagList += 'REVOKE' }
				if ($rdata.Flags -band 0x0001) { $flagList += 'SEP' }
				$flagDesc = if ($flagList.Count -gt 0) { $flagList -join ', ' } else { 'None' }
				$props['Flags'] = "$($rdata.Flags) ($flagDesc)"
				$props['KeyType'] = if ($rdata.Flags -band 1) { 'KSK' } else { 'ZSK' }
				$props['KeyTag'] = $rdata.KeyTag
				$props['Protocol'] = $rdata.Protocol
				$props['Algorithm'] = Format-DnssecAlgorithmName -Algorithm $rdata.Algorithm
			}
		}
		50 { # NSEC3
			if ($rdata) {
				$hashAlgName = switch ($rdata.HashAlgorithm) {
					1 { 'SHA-1' }
					default { 'Unknown' }
				}
				$props['HashAlgorithm'] = "$hashAlgName($($rdata.HashAlgorithm))"
				$optOut = if ($rdata.Flags -band 0x01) { 'Yes' } else { 'No' }
				$props['Flags'] = "$($rdata.Flags) (OptOut: $optOut)"
				$props['Iterations'] = $rdata.Iterations
				if ($rdata.TypeBitMaps) {
					$props['TypeBitMaps'] = ($rdata.TypeBitMaps | ForEach-Object { Format-DnsTypeName -Type $_ }) -join ', '
				}
			}
		}
		256 { # URI
			if ($rdata) {
				$props['Priority'] = $rdata.Priority
				$props['Weight'] = $rdata.Weight
				$props['Target'] = $rdata.Target
			}
		}
		257 { # CAA
			if ($rdata) {
				$props['Flags'] = $rdata.Flags
				$props['Tag'] = $rdata.Tag
				$props['Value'] = $rdata.Value
			}
		}
		default {
			# For unknown types, just show RDATA length
			$props['RDataLength'] = $Record.RDataLength
		}
	}

	return [PSCustomObject]$props
}
