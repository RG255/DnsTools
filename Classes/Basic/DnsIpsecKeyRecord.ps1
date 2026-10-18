class DnsIpsecKeyRecord {
	[byte]  $Precedence    # Like MX preference - lower is preferred
	[byte]  $GatewayType   # 0=none, 1=IPv4, 2=IPv6, 3=domain name
	[byte]  $Algorithm     # 0=none, 1=DSA, 2=RSA, 3=ECDSA
	[string]$Gateway       # Presentation form: '.', an IPv4/IPv6 address, or a domain name
	[byte[]]$PublicKey     # Raw public key (base64 in presentation)

	DnsIpsecKeyRecord([byte]$prec, [byte]$gwType, [byte]$alg, [string]$gw, [byte[]]$key)
	{
		$this.Precedence  = $prec
		$this.GatewayType = $gwType
		$this.Algorithm   = $alg
		$this.Gateway     = $gw
		$this.PublicKey   = $key
	}

	static [DnsIpsecKeyRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$startPos = $r.Position
		$prec   = $r.ReadUInt8()
		$gwType = $r.ReadUInt8()
		$alg    = $r.ReadUInt8()

		$gw = '.'
		switch ($gwType)
		{
			0 {$gw = '.'}
			1 {$gw = ([System.Net.IPAddress]::new($r.ReadBytes(4))).ToString()}
			2 {$gw = ([System.Net.IPAddress]::new($r.ReadBytes(16))).ToString()}
			3 {$gw = $r.ReadName()}
			default {throw "Invalid IPSECKEY gateway type: $gwType"}
		}

		$remaining = $len - ($r.Position - $startPos)
		[byte[]]$key = $r.ReadBytes([Math]::Max(0, $remaining))

		return [DnsIpsecKeyRecord]::new($prec, $gwType, $alg, $gw, $key)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt8($this.Precedence)
		$w.WriteUInt8($this.GatewayType)
		$w.WriteUInt8($this.Algorithm)
		switch ($this.GatewayType)
		{
			0 {}
			1 {$w.WriteBytes([System.Net.IPAddress]::Parse($this.Gateway).GetAddressBytes())}
			2 {$w.WriteBytes([System.Net.IPAddress]::Parse($this.Gateway).GetAddressBytes())}
			3 {$w.WriteName($this.Gateway)}
		}
		if ($this.PublicKey -and $this.PublicKey.Length -gt 0)
		{$w.WriteBytes($this.PublicKey)}
		return $w.ToArray()
	}

	[string]GetPublicKeyBase64()
	{return [Convert]::ToBase64String($this.PublicKey)}
}
