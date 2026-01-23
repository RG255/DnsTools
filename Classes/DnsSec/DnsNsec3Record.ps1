class DnsNsec3Record {
	[byte]  $HashAlgorithm
	[byte]  $Flags
	[uint16]$Iterations
	[byte[]]$Salt
	[byte[]]$OwnerHash
	[byte[]]$NextHash
	[int[]] $Types

	DnsNsec3Record(
		[byte]$alg,[byte]$flags,[uint16]$iter,
		[byte[]]$salt,[byte[]]$ownerHash,[byte[]]$nextHash,[int[]]$types
	)
	{
		$this.HashAlgorithm = $alg
		$this.Flags         = $flags
		$this.Iterations    = $iter
		$this.Salt          = $salt
		$this.OwnerHash     = $ownerHash
		$this.NextHash      = $nextHash
		$this.Types         = $types
	}

	static [DnsNsec3Record] Parse([byte[]]$rdata, [byte[]]$ownerHash)
	{
		$r          = [DnsBinaryReader]::new($rdata)
		$algVal     = $r.ReadUInt8()
		$flagsval   = $r.ReadUInt8()
		$iterval    = $r.ReadUInt16BE()
		$saltLenval = $r.ReadUInt8()
		$saltval    = if ($saltLenval -gt 0) 
		{$r.ReadBytes($saltLenval)}
		else 
		{[byte[]]@()}

		$hashLenval  = $r.ReadUInt8()
		$nextHashval = $r.ReadBytes($hashLenval)

		$typesval = New-Object -TypeName System.Collections.Generic.List[int]
		while ($r.Position -lt $r.Buffer.Length) 
		{
			$blockval = $r.ReadUInt8()
			$lenval   = $r.ReadUInt8()
			if ($lenval -lt 1 -or $lenval -gt 32) 
			{throw "Invalid NSEC3 bitmap length: $lenval"}
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

		return [DnsNsec3Record]::new(
			$algVal,$flagsval,$iterval,$saltval,
			$ownerHash,          # <-- NEW
			$nextHashval,
			$typesval.ToArray()
		)
	}
    
	[byte[]]ToWire() 
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt8($this.HashAlgorithm)
		$w.WriteUInt8($this.Flags)
		$w.WriteUInt16BE($this.Iterations)

		if ($this.Salt -and $this.Salt.Length -gt 0) 
		{
			$w.WriteUInt8([byte]$this.Salt.Length)
			$w.WriteBytes($this.Salt)
		}
		else 
		{$w.WriteUInt8(0)}

		$w.WriteUInt8([byte]$this.NextHash.Length)
		$w.WriteBytes($this.NextHash)

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