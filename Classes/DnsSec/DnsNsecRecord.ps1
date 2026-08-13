class DnsNsecRecord {
	[string] $NextDomainName
	[int[]]  $Types

	DnsNsecRecord([string]$next,[int[]]$types) 
	{
		$this.NextDomainName = $next
		$this.Types          = $types
	}

	static [string] ReadUncompressedName([DnsBinaryReader]$r) 
	{
		$labels = New-Object -TypeName System.Collections.Generic.List[string]

		while ($true) 
		{
			$len = $r.ReadUInt8()
			if ($len -eq 0) 
			{break}

			$labelBytes = $r.ReadBytes($len)
			$labels.Add([System.Text.Encoding]::ASCII.GetString($labelBytes))
		}

		return ($labels -join '.')
	}

	static [DnsNsecRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$startPos = $r.Position
		$endPos   = $startPos + $len
		$next = ([DnsNsecRecord]::ReadUncompressedName($r)).ToLowerInvariant()
		$typs = New-Object -TypeName System.Collections.Generic.List[int]

		while ($r.Position -lt $endPos) 
		{
			$block = $r.ReadUInt8()
			$len   = $r.ReadUInt8()

			if ($len -lt 1 -or $len -gt 32) 
			{throw "Invalid NSEC bitmap length: $len"}

			$bits  = $r.ReadBytes($len)

			for ($b = 0; $b -lt $bits.Length; $b++) 
			{
				for ($bit = 0; $bit -lt 8; $bit++) 
				{
					if ($bits[$b] -band (1 -shl (7-$bit))) 
					{$null = $typs.Add($block * 256 + $b*8 + $bit)}
				}
			}
		}

		return [DnsNsecRecord]::new($next, $typs.ToArray())
	}

	[byte[]]ToWire() 
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteName($this.NextDomainName)

		$byBlock = @{}
		foreach ($t in $this.Types) 
		{
			$block  = [int]([math]::Floor($t / 256))
			$offset = $t % 256
			if (-not $byBlock.ContainsKey($block)) 
			{$byBlock[$block] = New-Object -TypeName System.Collections.Generic.List[int]}
			$null = $byBlock[$block].Add($offset)
		}

		foreach ($kv in $byBlock.GetEnumerator() | Sort-Object -Property Key) 
		{
			$block   = [byte]$kv.Key
			$offsets = $kv.Value | Sort-Object
			$maxByte = [int]([math]::Floor(($offsets | Measure-Object -Maximum).Maximum / 8))
			$bitmap  = New-Object -TypeName 'byte[]' -ArgumentList ($maxByte+1)

			foreach ($o in $offsets) 
			{
				$b   = [int]([math]::Floor($o / 8))
				$bit = $o % 8
				$bitmap[$b] = $bitmap[$b] -bor (1 -shl (7-$bit))
			}

			$w.WriteUInt8($block)
			$w.WriteUInt8([byte]$bitmap.Length)
			$w.WriteBytes($bitmap)
		}

		return $w.ToArray()
	}
}