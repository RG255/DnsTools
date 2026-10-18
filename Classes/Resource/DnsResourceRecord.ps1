class DnsResourceRecord {
	[string] $Name
	[uint16] $Type
	[uint16] $Class
	[uint32] $Ttl
	[byte[]] $RawRData
	[object] $RDataObject

	DnsResourceRecord(
		[string]$name,
		[uint16]$type,
		[uint16]$class,
		[uint32]$ttl,
		[byte[]]$raw,
		[object]$obj
	)
	{
		$this.Name        = $name
		$this.Type        = $type
		$this.Class       = $class
		$this.Ttl         = $ttl
		$this.RawRData    = $raw
		$this.RDataObject = $obj
	}

	static [DnsResourceRecord] Parse([DnsBinaryReader]$r)
	{
		$nameValue     = $r.ReadName()
		$typeValue     = $r.ReadUInt16BE()
		$classValue    = $r.ReadUInt16BE()
		$ttlValue      = $r.ReadUInt32BE()
		$rdlengthValue = $r.ReadUInt16BE()
		# Save the position
		$start = $r.Position
		$objValue = [DnsResourceRecord]::ParseRDataTyped($typeValue, $r, $rdlengthValue, $nameValue)
		$r.Position = $start + $rdlengthValue
		# Zero-length RDATA: Buffer[start..(start-1)] is a descending range and would return two bytes.
		[byte[]]$rdataValue = [byte[]]@()
		if ($rdlengthValue -gt 0)
		{$rdataValue = $r.Buffer[$start..($start + $rdlengthValue - 1)]}

		return [DnsResourceRecord]::new(
			$nameValue,
			$typeValue,
			$classValue,
			$ttlValue,
			$rdataValue,
			$objValue
		)
	}

	static [object] ParseRDataTyped([uint16]$type, [DnsBinaryReader]$r, [int]$len, [string]$ownerName)
	{
		switch ($type) {
			1
			{return [DnsARecord]::Parse($r, $len)}
			2
			{return [DnsNsRecord]::Parse($r, $len)}
			28
			{return [DnsAaaaRecord]::Parse($r, $len)}
			5
			{return [DnsCnameRecord]::Parse($r, $len)}
			6
			{return [DnsSoaRecord]::Parse($r, $len)}
			12
			{return [DnsPtrRecord]::Parse($r, $len)}
			15
			{return [DnsMxRecord]::Parse($r, $len)}
			16
			{return [DnsTxtRecord]::Parse($r, $len)}
			33
			{return [DnsSrvRecord]::Parse($r, $len)}
			35
			{return [DnsNaptrRecord]::Parse($r, $len)}
			39
			{return [DnsDnameRecord]::Parse($r, $len)}
			48
			{return [DnsDnskeyRecord]::Parse($r, $len)}
			43
			{return [DnsDsRecord]::Parse($r, $len)}
			44
			{return [DnsSshfpRecord]::Parse($r, $len)}
			46
			{return [DnsRrsigRecord]::Parse($r, $len)}
			47
			{return [DnsNsecRecord]::Parse($r, $len)}
			50
			{return [DnsNsec3Record]::Parse($r, $len, $ownerName)}
			52
			{return [DnsTlsaRecord]::Parse($r, $len)}
			17
			{return [DnsRpRecord]::Parse($r, $len)}
			45
			{return [DnsIpsecKeyRecord]::Parse($r, $len)}
			61
			{return [DnsOpenPgpKeyRecord]::Parse($r, $len)}
			256
			{return [DnsUriRecord]::Parse($r, $len)}
			257
			{return [DnsCaaRecord]::Parse($r, $len)}
			default
			{return $null}
		}
		return $null
	}

	[void] Write([DnsBinaryWriter]$w)
	{
		$w.WriteName($this.Name)
		$w.WriteUInt16BE($this.Type)
		$w.WriteUInt16BE($this.Class)
		$w.WriteUInt32BE($this.Ttl)
		$w.WriteUInt16BE([uint16]$this.RawRData.Length)
		$w.WriteBytes($this.RawRData)
	}

	# RDATA in DNSSEC canonical form (RFC 4034 section 6.2). RawRData is a slice of the received packet, so
	# for types that embed domain names it may contain compression pointers and mixed-case names, neither
	# of which is what was signed. Rebuild those from the parsed object (ToWire writes uncompressed,
	# lower-cased names). Types: NS(2) CNAME(5) SOA(6) PTR(12) MX(15) RP(17) SRV(33) NAPTR(35) DNAME(39).
	# Everything else (A, AAAA, TXT, DNSKEY, DS, NSEC, RRSIG, ...) is already canonical as received.
	[byte[]] GetCanonicalRData()
	{
		if ($this.Type -in 2, 5, 6, 12, 15, 17, 33, 35, 39 -and $null -ne $this.RDataObject)
		{return $this.RDataObject.ToWire()}
		return $this.RawRData
	}

	[byte[]] ToCanonicalWire()
	{
		$rdata = $this.GetCanonicalRData()
		$w = [DnsBinaryWriter]::new()
		$w.WriteBytes( [byte[]](Get-DnssecCanonicalNameWire -name $this.Name) )
		$w.WriteUInt16BE($this.Type)
		$w.WriteUInt16BE($this.Class)
		$w.WriteUInt32BE($this.Ttl)
		$w.WriteUInt16BE([uint16]$rdata.Length)
		$w.WriteBytes($rdata)
		return $w.ToArray()
	}
}