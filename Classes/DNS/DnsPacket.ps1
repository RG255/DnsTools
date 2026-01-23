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
		$pktval = [DnsPacket]::new()
		$pktval.Header = [DnsHeader]::Parse($r)

		for ($i = 0; $i -lt $pktval.Header.QdCount; $i++) 
		{$null = $pktval.Questions.Add([DnsQuestion]::Parse($r))}

		for ($i = 0; $i -lt $pktval.Header.AnCount; $i++) 
		{
			if ($r.Position -ge $r.Buffer.Length) 
			{throw 'DNS header ANCOUNT exceeds packet length'}
			$null = $pktval.Answers.Add([DnsResourceRecord]::Parse($r))
		}

		for ($i = 0; $i -lt $pktval.Header.NsCount; $i++) 
		{
			if ($r.Position -ge $r.Buffer.Length) 
			{throw 'DNS header NSCOUNT exceeds packet length'}
			$null = $pktval.Authority.Add([DnsResourceRecord]::Parse($r))
		}

		for ($i = 0; $i -lt $pktval.Header.ArCount; $i++) 
		{
			$saved = $r.Position
			$r.ReadName()
			$type = $r.ReadUInt16BE()
			$r.Position = $saved

			if ($type -eq 41) 
			{
				if ($pktval.Opt) 
				{throw 'Multiple OPT records not allowed'}
				$pktval.Opt = [DnsOptRecord]::Parse($r)
			}
			else 
			{$null = $pktval.Additional.Add([DnsResourceRecord]::Parse($r))}
		}

		return $pktval
	}

	[byte[]] ToArray() 
	{
		$w = [DnsBinaryWriter]::new()

		$optCount = if ($this.Opt) 
		{1}
		else 
		{0}
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
