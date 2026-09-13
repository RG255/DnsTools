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

		$udp  = $r.ReadUInt16BE()
		$rcode = $r.ReadUInt8()
		$ver  = $r.ReadUInt8()
		$flgs    = $r.ReadUInt16BE()
		$rdlen = $r.ReadUInt16BE()
		[byte[]]$opts = $null
		if ($rdlen -gt 0) {
			$opts = $r.ReadBytes($rdlen)
		} else {
			$opts = [byte[]]@()
		}

		return [DnsOptRecord]::new(
			$udp, $rcode, $ver, $flgs, $opts
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