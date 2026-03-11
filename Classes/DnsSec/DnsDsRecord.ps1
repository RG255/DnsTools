class DnsDsRecord {
	[uint16]$KeyTag
	[byte]  $Algorithm
	[byte]  $DigestType
	[byte[]]$Digest

	DnsDsRecord([uint16]$tag,[byte]$alg,[byte]$dtype,[byte[]]$digest) 
	{
		$this.KeyTag     = $tag
		$this.Algorithm  = $alg
		$this.DigestType = $dtype
		$this.Digest     = $digest
	}

	static [DnsDsRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$startPos = $r.Position
		$tag  = $r.ReadUInt16BE()
		$alg  = $r.ReadUInt8()
		$dtype = $r.ReadUInt8()
		$remaining = $len - ($r.Position - $startPos)
		$dig  = $r.ReadBytes($remaining)
		return [DnsDsRecord]::new($tag,$alg,$dtype,$dig)
	}

	[byte[]]ToWire() 
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE($this.KeyTag)
		$w.WriteUInt8($this.Algorithm)
		$w.WriteUInt8($this.DigestType)
		$w.WriteBytes($this.Digest)
		return $w.ToArray()
	}

	[string] GetDigestHex() 
	{
		return ($this.Digest | ForEach-Object -Process {$_.ToString('x2')}) -join ''
	}
}