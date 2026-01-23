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

	static [DnsDsRecord] Parse([byte[]]$rdata) 
	{
		$r       = [DnsBinaryReader]::new($rdata)
		$tagval  = $r.ReadUInt16BE()
		$algVal  = $r.ReadUInt8()
		$dtypeval = $r.ReadUInt8()
		$digval  = $r.ReadBytes($rdata.Length - $r.Position)
		return [DnsDsRecord]::new($tagval,$algVal,$dtypeval,$digval)
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