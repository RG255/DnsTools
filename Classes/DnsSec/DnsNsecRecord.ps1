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

	static [DnsNsecRecord] Parse([byte[]]$rdata) 
	{
		$r        = [DnsBinaryReader]::new($rdata)
		$nextval = ([DnsNsecRecord]::ReadUncompressedName($r)).ToLowerInvariant()
		$typesval = New-Object -TypeName System.Collections.Generic.List[int]

		while ($r.Position -lt $r.Buffer.Length) 
		{
			$blockval = $r.ReadUInt8()
			$lenval   = $r.ReadUInt8()

			if ($lenval -lt 1 -or $lenval -gt 32) 
			{throw "Invalid NSEC bitmap length: $lenval"}

			$bitsval  = $r.ReadBytes($lenval)

			for ($b = 0; $b -lt $bitsval.Length; $b++) 
			{
				for ($bit = 0; $bit -lt 8; $bit++) 
				{
					if ($bitsval[$b] -band (1 -shl (7-$bit))) 
					{$null = $typesval.Add($blockval * 256 + $b*8 + $bit)}
				}
			}
		}

		return [DnsNsecRecord]::new($nextval, $typesval.ToArray())
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