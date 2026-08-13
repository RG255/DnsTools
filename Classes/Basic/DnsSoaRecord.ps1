class DnsSoaRecord {
	[string]$MName      # Primary nameserver
	[string]$RName      # Responsible person email (@ replaced with .)
	[uint32]$Serial     # Zone serial number
	[uint32]$Refresh    # Seconds between zone refreshes
	[uint32]$Retry      # Seconds between retry attempts
	[uint32]$Expire     # Seconds until zone is no longer authoritative
	[uint32]$Minimum    # Minimum TTL for negative caching

	DnsSoaRecord(
		[string]$mname,
		[string]$rname,
		[uint32]$serial,
		[uint32]$refresh,
		[uint32]$retry,
		[uint32]$expire,
		[uint32]$minimum
	)
	{
		$this.MName   = $mname
		$this.RName   = $rname
		$this.Serial  = $serial
		$this.Refresh = $refresh
		$this.Retry   = $retry
		$this.Expire  = $expire
		$this.Minimum = $minimum
	}

	static [DnsSoaRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$mn   = $r.ReadName()
		$rn   = $r.ReadName()
		$ser  = $r.ReadUInt32BE()
		$rfr = $r.ReadUInt32BE()
		$rty   = $r.ReadUInt32BE()
		$xpr  = $r.ReadUInt32BE()
		$min = $r.ReadUInt32BE()

		return [DnsSoaRecord]::new(
			$mn, $rn, $ser,
			$rfr, $rty, $xpr, $min
		)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteName($this.MName)
		$w.WriteName($this.RName)
		$w.WriteUInt32BE($this.Serial)
		$w.WriteUInt32BE($this.Refresh)
		$w.WriteUInt32BE($this.Retry)
		$w.WriteUInt32BE($this.Expire)
		$w.WriteUInt32BE($this.Minimum)
		return $w.ToArray()
	}
}
