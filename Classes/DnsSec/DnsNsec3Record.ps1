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
		[byte[]]$salt,[byte[]]$oHash,[byte[]]$nextHash,[int[]]$types
	)
	{
		$this.HashAlgorithm = $alg
		$this.Flags         = $flags
		$this.Iterations    = $iter
		$this.Salt          = $salt
		$this.OwnerHash     = $oHash
		$this.NextHash      = $nextHash
		$this.Types         = $types
	}

	static [byte[]] Base32HexDecode([string]$encoded)
	{
		# RFC 4648 Base32hex alphabet: 0-9, A-V (uppercase)
		$alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV'
		$encoded = $encoded.ToUpper().Replace('=', '')

		if ($encoded.Length -eq 0) { return [byte[]]@() }

		$bits = ''
		foreach ($char in $encoded.ToCharArray())
		{
			$val = $alphabet.IndexOf($char)
			if ($val -eq -1) { throw "Invalid Base32hex character: $char" }
			$bits += [Convert]::ToString($val, 2).PadLeft(5, '0')
		}

		$bytes = [System.Collections.Generic.List[byte]]::new()
		for ($i = 0; $i -lt $bits.Length - 7; $i += 8)
		{
			$byteStr = $bits.Substring($i, 8)
			$bytes.Add([Convert]::ToByte($byteStr, 2))
		}

		return [byte[]]$bytes.ToArray()
	}

	static [DnsNsec3Record] Parse([DnsBinaryReader]$r, [int]$len, [string]$ownerName)
	{
		$startPos   = $r.Position
		$endPos     = $startPos + $len

		# Extract owner hash from base32hex-encoded first label of owner name
		$firstLabel = $ownerName.Split('.')[0].ToUpper()
		$oHash = [DnsNsec3Record]::Base32HexDecode($firstLabel)

		$alg     = $r.ReadUInt8()
		$flgs   = $r.ReadUInt8()
		$iter    = $r.ReadUInt16BE()
		$saltLen = $r.ReadUInt8()
		# Typed statement-form assignment: with `$x = if (...) {...} else {[byte[]]@()}` an EMPTY salt (the common NSEC3
		# case) was unrolled to $null, so Salt was $null instead of an empty array.
		[byte[]]$slt = $r.ReadBytes($saltLen)

		$hashLen  = $r.ReadUInt8()
		$nxtHash = $r.ReadBytes($hashLen)

		$typs = New-Object -TypeName System.Collections.Generic.List[int]
		while ($r.Position -lt $endPos)
		{
			$block = $r.ReadUInt8()
			$len   = $r.ReadUInt8()
			if ($len -lt 1 -or $len -gt 32)
			{throw "Invalid NSEC3 bitmap length: $len"}
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

		return [DnsNsec3Record]::new(
			$alg,$flgs,$iter,$slt,
			$oHash,
			$nxtHash,
			$typs.ToArray()
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