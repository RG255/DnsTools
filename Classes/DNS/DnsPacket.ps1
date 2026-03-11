class DnsPacket {
	[DnsHeader] $Header
	[System.Collections.Generic.List[DnsQuestion]] $Questions
	[System.Collections.Generic.List[DnsResourceRecord]] $Answers
	[System.Collections.Generic.List[DnsResourceRecord]] $Authority
	[System.Collections.Generic.List[DnsResourceRecord]] $Additional
	[DnsOptRecord] $Opt

	DnsPacket() 
	{
		$this.Questions  = [System.Collections.Generic.List[DnsQuestion]]::new()
		$this.Answers    = [System.Collections.Generic.List[DnsResourceRecord]]::new()
		$this.Authority  = [System.Collections.Generic.List[DnsResourceRecord]]::new()
		$this.Additional = [System.Collections.Generic.List[DnsResourceRecord]]::new()
		$this.Opt        = $null
	}

	static [DnsPacket] Parse([byte[]]$packetBytes) 
	{
		$r = [DnsBinaryReader]::new($packetBytes)
		$pkt = [DnsPacket]::new()
		$pkt.Header = [DnsHeader]::Parse($r)

		for ($i = 0; $i -lt $pkt.Header.QdCount; $i++) 
		{$null = $pkt.Questions.Add([DnsQuestion]::Parse($r))}

		for ($i = 0; $i -lt $pkt.Header.AnCount; $i++) 
		{
			if ($r.Position -ge $r.Buffer.Length) 
			{throw 'DNS header ANCOUNT exceeds packet length'}
			$null = $pkt.Answers.Add([DnsResourceRecord]::Parse($r))
		}

		for ($i = 0; $i -lt $pkt.Header.NsCount; $i++) 
		{
			if ($r.Position -ge $r.Buffer.Length) 
			{throw 'DNS header NSCOUNT exceeds packet length'}
			$null = $pkt.Authority.Add([DnsResourceRecord]::Parse($r))
		}

		for ($i = 0; $i -lt $pkt.Header.ArCount; $i++)
		{
			$saved = $r.Position

			# OPT records always have name = root (single 0x00 byte)
			# Check the first byte to determine if this might be an OPT record
			$firstByte = $r.ReadUInt8()
			$r.Position = $saved

			# If first byte is 0x00, peek at the type to confirm it's OPT
			if ($firstByte -eq 0)
			{
				$r.Position = $saved + 1  # Skip the 0x00 name
				$type = $r.ReadUInt16BE()
				$r.Position = $saved

				if ($type -eq 41)
				{
					if ($pkt.Opt)
					{throw 'Multiple OPT records not allowed'}
					$pkt.Opt = [DnsOptRecord]::Parse($r)
					continue
				}
			}

			# Not an OPT record, parse as regular resource record
			$null = $pkt.Additional.Add([DnsResourceRecord]::Parse($r))
		}

		return $pkt
	}

	[byte[]] ToArray()
	{
		$w = [DnsBinaryWriter]::new()

		$optCount = if ($this.Opt) {1} else {0}
		$this.Header.ArCount = $this.Additional.Count + $optCount

		$this.Header.Write($w)

		foreach ($q in $this.Questions)
		{$q.Write($w)}
		foreach ($rr in $this.Answers)
		{$rr.Write($w)}
		foreach ($rr in $this.Authority)
		{$rr.Write($w)}
		foreach ($rr in $this.Additional)
		{$rr.Write($w)}

		if ($this.Opt)
		{$this.Opt.Write($w)}

		return $w.ToArray()
	}
}
