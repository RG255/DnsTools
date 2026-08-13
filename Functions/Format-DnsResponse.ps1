function Format-DnsResponse
{
	<#
	.SYNOPSIS
		Formats DNS response records into user-readable objects.

	.DESCRIPTION
		Converts DNS resource records into formatted objects similar to PowerShell's Resolve-DnsName output,
		with properties like Name, Type, TTL, Section, and type-specific data fields.

	.PARAMETER Records
		Array of DNS resource records to format.

	.PARAMETER Section
		The section these records came from (Answer, Authority, Additional).

	.EXAMPLE
		Format-DnsResponse -Records $response.Answers -Section 'Answer'
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[Array]$Records,

		[Parameter(Mandatory)]
		[ValidateSet('Answer', 'Authority', 'Additional')]
		[string]$Section
	)

	foreach ($record in $Records) {
		$baseProps = [ordered]@{
			Name       = $record.Name
			Type       = Format-DnsTypeName -Type $record.Type
			TTL        = $record.Ttl
			DataLength = $record.RDataLength
			Section    = $Section
		}

		# Add type-specific properties
		if ($record.RDataObject) {
			$rdata = $record.RDataObject

			switch ($record.Type) {
				1 {
					# A record
					$baseProps['IPAddress'] = $rdata.Address
				}
				28 {
					# AAAA record
					$baseProps['IPAddress'] = $rdata.Address
				}
				2 {
					# NS record
					$baseProps['NameHost'] = $rdata.NsName
				}
				5 {
					# CNAME record
					$baseProps['HostNameAlias'] = $rdata.CName
				}
				6 {
					# SOA record
					$baseProps['PrimaryServer'] = $rdata.MName
					$baseProps['NameAdministrator'] = $rdata.RName
					$baseProps['SerialNumber'] = $rdata.Serial
					$baseProps['TimeToZoneRefresh'] = $rdata.Refresh
					$baseProps['TimeToZoneFailureRetry'] = $rdata.Retry
					$baseProps['TimeToExpiration'] = $rdata.Expire
					$baseProps['DefaultTTL'] = $rdata.Minimum
				}
				12 {
					# PTR record
					$baseProps['NameHost'] = $rdata.PtrName
				}
				15 {
					# MX record
					$baseProps['Preference'] = $rdata.Preference
					$baseProps['MailExchange'] = $rdata.Exchange
				}
				16 {
					# TXT record
					$baseProps['Strings'] = $rdata.Text -join '; '
				}
				33 {
					# SRV record
					$baseProps['Priority'] = $rdata.Priority
					$baseProps['Weight'] = $rdata.Weight
					$baseProps['Port'] = $rdata.Port
					$baseProps['NameTarget'] = $rdata.Target
				}
				43 {
					# DS record
					$baseProps['KeyTag'] = $rdata.KeyTag
					$baseProps['Algorithm'] = Format-DnssecAlgorithmName -Algorithm $rdata.Algorithm
					$baseProps['DigestType'] = $rdata.DigestType
					$baseProps['Digest'] = ConvertTo-HexString -bytes $rdata.Digest -MaxLength 40
				}
				48 {
					# DNSKEY record
					$baseProps['Flags'] = $rdata.Flags
					$baseProps['Protocol'] = $rdata.Protocol
					$baseProps['Algorithm'] = Format-DnssecAlgorithmName -Algorithm $rdata.Algorithm
					$baseProps['KeyTag'] = $rdata.KeyTag
					$baseProps['PublicKey'] = ConvertTo-HexString -bytes $rdata.PublicKey -MaxLength 40
				}
				46 {
					# RRSIG record
					$baseProps['TypeCovered'] = Format-DnsTypeName -Type $rdata.TypeCovered
					$baseProps['Algorithm'] = Format-DnssecAlgorithmName -Algorithm $rdata.Algorithm
					$baseProps['Labels'] = $rdata.Labels
					$baseProps['OriginalTTL'] = $rdata.OriginalTtl
					$baseProps['Expiration'] = $rdata.Expiration
					$baseProps['Inception'] = $rdata.Inception
					$baseProps['KeyTag'] = $rdata.KeyTag
					$baseProps['SignerName'] = $rdata.SignerName
				}
				257 {
					# CAA record
					$baseProps['Flags'] = $rdata.Flags
					$baseProps['Tag'] = $rdata.Tag
					$baseProps['Value'] = $rdata.Value
				}
				default {
					# Generic record - show raw data hex
					if ($record.RData -and $record.RData.Length -gt 0) {
						$baseProps['Data'] = ConvertTo-HexString -bytes $record.RData -MaxLength 60
					}
				}
			}
		}

		[PSCustomObject]$baseProps
	}
}
