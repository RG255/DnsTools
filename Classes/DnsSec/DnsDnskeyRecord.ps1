class DnsDnskeyRecord {
	[uint16]$Flags
	[byte]  $Protocol
	[byte]  $Algorithm
	[byte[]]$PublicKey
	[uint16]$KeyTag

	DnsDnskeyRecord([uint16]$flags,[byte]$proto,[byte]$alg,[byte[]]$key)
	{
		$this.Flags     = $flags
		$this.Protocol  = $proto
		$this.Algorithm = $alg
		$this.PublicKey = $key
		$this.KeyTag = [DnsDnskeyRecord]::ComputeKeyTag($flags, $proto, $alg, $key)
	}

	static [DnsDnskeyRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$startPos = $r.Position
		$flgs = $r.ReadUInt16BE()
		$proto = $r.ReadUInt8()
		$alg   = $r.ReadUInt8()
		$remaining = $len - ($r.Position - $startPos)
		$key   = $r.ReadBytes($remaining)
		return [DnsDnskeyRecord]::new($flgs, $proto, $alg, $key)
	}

	static [uint16] ComputeKeyTag(
		[uint16]$flags,
		[byte]$proto,
		[byte]$alg,
		[byte[]]$key
	)
	{
		$sum = 0
		$rdata = New-Object -TypeName System.Collections.Generic.List[byte]

		$flagsBytes = [BitConverter]::GetBytes($flags)
		if ([BitConverter]::IsLittleEndian)
		{[Array]::Reverse($flagsBytes)}
		$rdata.AddRange($flagsBytes)

		$rdata.Add($proto)
		$rdata.Add($alg)
		$rdata.AddRange($key)

		$i = 0
		foreach ($b in $rdata)
		{
			if ($i % 2 -eq 0)
			{$sum += $b * 256}
			else
			{$sum += $b}
			$i++
		}

		# Proper carry fold: (sum & 0xFFFF) + (sum >> 16)
		$sum = ($sum -band 0xFFFF) + ($sum -shr 16)

		return [uint16]($sum -band 0xFFFF)
	}
}
