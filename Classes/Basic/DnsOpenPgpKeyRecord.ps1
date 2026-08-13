class DnsOpenPgpKeyRecord {
	[byte[]]$PublicKey     # OpenPGP transferable public key (raw bytes; base64 in presentation)

	DnsOpenPgpKeyRecord([byte[]]$key)
	{$this.PublicKey = $key}

	static [DnsOpenPgpKeyRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$key = if ($len -gt 0) {$r.ReadBytes($len)} else {[byte[]]@()}
		return [DnsOpenPgpKeyRecord]::new($key)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		if ($this.PublicKey -and $this.PublicKey.Length -gt 0)
		{$w.WriteBytes($this.PublicKey)}
		return $w.ToArray()
	}

	[string]GetPublicKeyBase64()
	{return [Convert]::ToBase64String($this.PublicKey)}
}
