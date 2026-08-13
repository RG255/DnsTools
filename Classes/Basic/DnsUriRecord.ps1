class DnsUriRecord {
	[uint16]$Priority
	[uint16]$Weight
	[string]$Target

	DnsUriRecord([uint16]$priority, [uint16]$weight, [string]$target)
	{
		$this.Priority = $priority
		$this.Weight   = $weight
		$this.Target   = $target
	}

	static [DnsUriRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$pri = $r.ReadUInt16BE()
		$wgt = $r.ReadUInt16BE()

		# Target is a character-string (raw bytes, not length-prefixed in URI)
		# Remaining length after priority and weight is len - 4
		$tgtLen = $len - 4
		if ($tgtLen -gt 0) {
			$tgtBytes = $r.ReadBytes($tgtLen)
			$tgt = [System.Text.Encoding]::ASCII.GetString($tgtBytes)
		} else {
			$tgt = ''
		}

		return [DnsUriRecord]::new($pri, $wgt, $tgt)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE($this.Priority)
		$w.WriteUInt16BE($this.Weight)
		$bytes = [System.Text.Encoding]::ASCII.GetBytes($this.Target)
		$w.WriteBytes($bytes)
		return $w.ToArray()
	}
}
