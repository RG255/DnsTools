class DnsTlsaRecord {
	[byte]$CertUsage           # 0-3: PKIX-TA, PKIX-EE, DANE-TA, DANE-EE
	[byte]$Selector            # 0=Full cert, 1=SubjectPublicKeyInfo
	[byte]$MatchingType        # 0=Full, 1=SHA-256, 2=SHA-512
	[byte[]]$CertificateData   # Certificate association data

	DnsTlsaRecord([byte]$usage, [byte]$sel, [byte]$matching, [byte[]]$data)
	{
		$this.CertUsage = $usage
		$this.Selector = $sel
		$this.MatchingType = $matching
		$this.CertificateData = $data
	}

	static [DnsTlsaRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$startPos = $r.Position
		$usage = $r.ReadUInt8()
		$sel = $r.ReadUInt8()
		$mtch = $r.ReadUInt8()
		$remaining = $len - ($r.Position - $startPos)
		$data = $r.ReadBytes($remaining)

		return [DnsTlsaRecord]::new($usage, $sel, $mtch, $data)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt8($this.CertUsage)
		$w.WriteUInt8($this.Selector)
		$w.WriteUInt8($this.MatchingType)
		$w.WriteBytes($this.CertificateData)
		return $w.ToArray()
	}
}
