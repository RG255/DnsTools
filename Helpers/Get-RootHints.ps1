function Get-RootHintsObject 
{
	# URI to obtain the root hints file
	$URI_RH = 'https://www.internic.net/domain/named.root'

	try 
	{$RHDataIn = -join [char[]](Invoke-WebRequest -Uri $URI_RH -UseBasicParsing).Content}
	catch 
	{
		Write-Warning -Message "Unable to obtain root hints from: [$URI_RH]"
		return $null
	}

	# Initialise storage
	$RootServers = @()
	$RootServerMap = @{}

	# Split into lines
	$lines = $RHDataIn -split "`n" | ForEach-Object -Process {$_.Trim()}

	foreach ($line in $lines) 
	{
		# Skip comments and blanks
		if ($line -match '^\s*;') 
		{continue}
		if ($line -eq '') 
		{continue}

		# NS record
		if ($line -match '^\.\s+\d+\s+NS\s+([A-Za-z0-9\.\-]+)\.?$') 
		{
			$hn = $Matches[1].ToUpper() + '.'
			$entry = [ordered]@{
				Name     = '.'
				HostName = $hn
				IPv4     = $null
				IPv6     = $null
			}
			$RootServers += $entry
			$RootServerMap[$hn] = $entry
			continue
		}

		# IPv4 glue
		if ($line -match '^([A-Za-z0-9\.\-]+)\.?\s+\d+\s+A\s+([0-9\.]+)$') 
		{
			$hn   = $Matches[1].ToUpper() + '.'
			$addr = $Matches[2]
			if ($RootServerMap.ContainsKey($hn)) 
			{$RootServerMap[$hn].IPv4 = $addr}
			continue
		}

		# IPv6 glue
		if ($line -match '^([A-Za-z0-9\.\-]+)\.?\s+\d+\s+AAAA\s+([0-9A-Fa-f:]+)$') 
		{
			$hn   = $Matches[1].ToUpper() + '.'
			$addr = $Matches[2]
			if ($RootServerMap.ContainsKey($hn)) 
			{$RootServerMap[$hn].IPv6 = $addr}
			continue
		}
	}

	# Build flat list of usable IPs
	$RootServerAddresses = 
	$RootServers |
	ForEach-Object -Process {
		@($_.IPv4, $_.IPv6) | Where-Object -FilterScript {$_} 
	}

	# Return a composite object
	[pscustomobject]@{
		RootServers         = $RootServers
		RootServerAddresses = $RootServerAddresses
	}
}
Get-RootHintsObject