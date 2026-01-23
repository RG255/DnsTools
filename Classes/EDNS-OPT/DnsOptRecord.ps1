class DnsOptRecord {
	[uint16]$UdpPayloadSize
	[byte]  $ExtendedRcode
	[byte]  $Version
	[uint16]$Flags
	[byte[]]$Options

	DnsOptRecord(
		[uint16]$udp,
		[byte]$rcode,
		[byte]$ver,
		[uint16]$flags,
		[byte[]]$opts
	) 
	{
		$this.UdpPayloadSize = $udp
		$this.ExtendedRcode  = $rcode
		$this.Version        = $ver
		$this.Flags          = $flags
		$this.Options        = $opts
	}

	static [DnsOptRecord] Parse([DnsBinaryReader]$r) 
	{
		$name = $r.ReadUInt8()
		if ($name -ne 0) 
		{throw 'Invalid OPT NAME (must be root)'}

		$type = $r.ReadUInt16BE()
		if ($type -ne 41) 
		{throw 'Invalid OPT TYPE'}

		$udpSizeval  = $r.ReadUInt16BE()
		$extRcodeval = $r.ReadUInt8()
		$versionval  = $r.ReadUInt8()
		$flagsval    = $r.ReadUInt16BE()
		$rdlenval    = $r.ReadUInt16BE()
		$optsval     = if ($rdlenval -gt 0) 
		{$r.ReadBytes($rdlenval)}
		else 
		{@()}

		return [DnsOptRecord]::new(
			$udpSizeval, $extRcodeval, $versionval, $flagsval, $optsval
		)
	}

	[void]Write([DnsBinaryWriter]$w) 
	{
		$w.WriteUInt8(0)
		$w.WriteUInt16BE(41)
		$w.WriteUInt16BE($this.UdpPayloadSize)
		$w.WriteUInt8($this.ExtendedRcode)
		$w.WriteUInt8($this.Version)
		$w.WriteUInt16BE($this.Flags)
		$w.WriteUInt16BE($this.Options.Length)
		$w.WriteBytes($this.Options)
	}
}