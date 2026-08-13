class DnsSshfpRecord {
	[byte]$Algorithm          # 1=RSA, 2=DSS, 3=ECDSA, 4=Ed25519
	[byte]$FingerprintType    # 1=SHA-1, 2=SHA-256
	[byte[]]$Fingerprint      # Public key fingerprint

	DnsSshfpRecord([byte]$alg, [byte]$fpType, [byte[]]$fp)
	{
		$this.Algorithm = $alg
		$this.FingerprintType = $fpType
		$this.Fingerprint = $fp
	}

	static [DnsSshfpRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$startPos = $r.Position
		$alg = $r.ReadUInt8()
		$fpt = $r.ReadUInt8()
		$remaining = $len - ($r.Position - $startPos)
		$fp = $r.ReadBytes($remaining)

		return [DnsSshfpRecord]::new($alg, $fpt, $fp)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt8($this.Algorithm)
		$w.WriteUInt8($this.FingerprintType)
		$w.WriteBytes($this.Fingerprint)
		return $w.ToArray()
	}

	[string]GetFingerprintHex()
	{
		return ($this.Fingerprint | ForEach-Object { $_.ToString('x2') }) -join ''
	}
}
