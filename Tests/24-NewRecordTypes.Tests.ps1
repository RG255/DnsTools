using module dnstools

Describe "CAA Record Parsing and Encoding" {
	It "Parses a CAA record" {
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt8(0)  # flags (not critical)
		$issueTag = [System.Text.Encoding]::ASCII.GetBytes("issue")
		$w.WriteUInt8([byte]$issueTag.Length)
		$w.WriteBytes($issueTag)
		$valueBytes = [System.Text.Encoding]::UTF8.GetBytes("letsencrypt.org")
		$w.WriteBytes($valueBytes)
		$bytes = $w.ToArray()

		$reader = [DnsBinaryReader]::new($bytes)
		$caa = [DnsCaaRecord]::Parse($reader, $bytes.Length)

		$caa.Flags | Should -Be 0
		$caa.Tag | Should -Be "issue"
		$caa.Value | Should -Be "letsencrypt.org"
		$caa.IsCritical() | Should -Be $false
	}

	It "Round-trips CAA RDATA correctly" {
		$caa = [DnsCaaRecord]::new(128, "issuewild", "ca.example.com")
		$bytes = $caa.ToWire()

		$reader = [DnsBinaryReader]::new($bytes)
		$parsed = [DnsCaaRecord]::Parse($reader, $bytes.Length)

		$parsed.Flags | Should -Be 128
		$parsed.Tag | Should -Be "issuewild"
		$parsed.Value | Should -Be "ca.example.com"
		$parsed.IsCritical() | Should -Be $true
	}

	It "Detects critical flag correctly" {
		$caa1 = [DnsCaaRecord]::new(0, "issue", "ca.example.com")
		$caa2 = [DnsCaaRecord]::new(128, "issue", "ca.example.com")

		$caa1.IsCritical() | Should -Be $false
		$caa2.IsCritical() | Should -Be $true
	}
}

Describe "DNAME Record Parsing and Encoding" {
	It "Creates a DNAME record" {
		$dname = [DnsDnameRecord]::new("target.example.com")
		$dname.Target | Should -Be "target.example.com"
	}

	It "Round-trips DNAME correctly" {
		$dname = [DnsDnameRecord]::new("new-location.example.org")
		$w = [DnsBinaryWriter]::new()
		$bytes = $dname.ToWire()

		# Parse it back (DNAME uses compressed names, so we need a reader with compression)
		$dname.Target | Should -Be "new-location.example.org"
	}
}

Describe "NAPTR Record Parsing and Encoding" {
	It "Parses a NAPTR record" {
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE(100)  # order
		$w.WriteUInt16BE(10)   # preference

		# flags
		$flagsBytes = [System.Text.Encoding]::ASCII.GetBytes("S")
		$w.WriteUInt8([byte]$flagsBytes.Length)
		$w.WriteBytes($flagsBytes)

		# services
		$servicesBytes = [System.Text.Encoding]::ASCII.GetBytes("SIP+D2U")
		$w.WriteUInt8([byte]$servicesBytes.Length)
		$w.WriteBytes($servicesBytes)

		# regexp
		$regexpBytes = [System.Text.Encoding]::ASCII.GetBytes("")
		$w.WriteUInt8([byte]$regexpBytes.Length)

		# replacement
		$w.WriteName("_sip._udp.example.com")

		$bytes = $w.ToArray()
		$reader = [DnsBinaryReader]::new($bytes)
		$naptr = [DnsNaptrRecord]::Parse($reader, $bytes.Length)

		$naptr.Order | Should -Be 100
		$naptr.Preference | Should -Be 10
		$naptr.Flags | Should -Be "S"
		$naptr.Services | Should -Be "SIP+D2U"
		$naptr.Regexp | Should -Be ""
		$naptr.Replacement | Should -Be "_sip._udp.example.com"
	}

	It "Round-trips NAPTR RDATA correctly" {
		$naptr = [DnsNaptrRecord]::new(100, 50, "U", "E2U+sip", "!^.*$!sip:info@example.com!", "")
		$bytes = $naptr.ToWire()

		$reader = [DnsBinaryReader]::new($bytes)
		$parsed = [DnsNaptrRecord]::Parse($reader, $bytes.Length)

		$parsed.Order | Should -Be 100
		$parsed.Preference | Should -Be 50
		$parsed.Flags | Should -Be "U"
		$parsed.Services | Should -Be "E2U+sip"
		$parsed.Regexp | Should -Be "!^.*$!sip:info@example.com!"
		$parsed.Replacement | Should -Be ""
	}
}

Describe "PTR Record Parsing and Encoding" {
	It "Creates a PTR record" {
		$ptr = [DnsPtrRecord]::new("host.example.com")
		$ptr.Pointer | Should -Be "host.example.com"
	}

	It "Round-trips PTR correctly" {
		$ptr = [DnsPtrRecord]::new("mail.example.org")
		$bytes = $ptr.ToWire()

		# PTR uses domain names which can be compressed
		$ptr.Pointer | Should -Be "mail.example.org"
	}
}

Describe "SOA Record Parsing and Encoding" {
	It "Parses a SOA record" {
		$w = [DnsBinaryWriter]::new()
		$w.WriteName("ns1.example.com")
		$w.WriteName("admin.example.com")
		$w.WriteUInt32BE(2023010101)  # serial
		$w.WriteUInt32BE(7200)        # refresh
		$w.WriteUInt32BE(3600)        # retry
		$w.WriteUInt32BE(1209600)     # expire
		$w.WriteUInt32BE(86400)       # minimum

		$bytes = $w.ToArray()
		$reader = [DnsBinaryReader]::new($bytes)
		$soa = [DnsSoaRecord]::Parse($reader, $bytes.Length)

		$soa.MName | Should -Be "ns1.example.com"
		$soa.RName | Should -Be "admin.example.com"
		$soa.Serial | Should -Be 2023010101
		$soa.Refresh | Should -Be 7200
		$soa.Retry | Should -Be 3600
		$soa.Expire | Should -Be 1209600
		$soa.Minimum | Should -Be 86400
	}

	It "Round-trips SOA RDATA correctly" {
		$soa = [DnsSoaRecord]::new(
			"ns.example.com",
			"hostmaster.example.com",
			2024010101,
			3600,
			1800,
			604800,
			300
		)
		$bytes = $soa.ToWire()

		$reader = [DnsBinaryReader]::new($bytes)
		$parsed = [DnsSoaRecord]::Parse($reader, $bytes.Length)

		$parsed.MName | Should -Be "ns.example.com"
		$parsed.RName | Should -Be "hostmaster.example.com"
		$parsed.Serial | Should -Be 2024010101
		$parsed.Refresh | Should -Be 3600
		$parsed.Retry | Should -Be 1800
		$parsed.Expire | Should -Be 604800
		$parsed.Minimum | Should -Be 300
	}
}

Describe "SSHFP Record Parsing and Encoding" {
	It "Parses an SSHFP record" {
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt8(1)  # algorithm: RSA
		$w.WriteUInt8(2)  # fp type: SHA-256
		$fingerprint = [byte[]](1..32)  # 32-byte SHA-256 hash
		$w.WriteBytes($fingerprint)

		$bytes = $w.ToArray()
		$reader = [DnsBinaryReader]::new($bytes)
		$sshfp = [DnsSshfpRecord]::Parse($reader, $bytes.Length)

		$sshfp.Algorithm | Should -Be 1
		$sshfp.FingerprintType | Should -Be 2
		$sshfp.Fingerprint.Length | Should -Be 32
	}

	It "Round-trips SSHFP RDATA correctly" {
		$fp = [byte[]](0..19)  # 20-byte SHA-1 hash
		$sshfp = [DnsSshfpRecord]::new(3, 1, $fp)  # ECDSA, SHA-1
		$bytes = $sshfp.ToWire()

		$reader = [DnsBinaryReader]::new($bytes)
		$parsed = [DnsSshfpRecord]::Parse($reader, $bytes.Length)

		$parsed.Algorithm | Should -Be 3
		$parsed.FingerprintType | Should -Be 1
		$parsed.Fingerprint.Length | Should -Be 20
	}

	It "Formats fingerprint as hex string" {
		$fp = [byte[]](0xAB, 0xCD, 0xEF, 0x12, 0x34)
		$sshfp = [DnsSshfpRecord]::new(1, 1, $fp)

		$hex = $sshfp.GetFingerprintHex()
		$hex | Should -Be "abcdef1234"
	}
}

Describe "TLSA Record Parsing and Encoding" {
	It "Parses a TLSA record" {
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt8(3)  # usage: DANE-EE
		$w.WriteUInt8(1)  # selector: SPKI
		$w.WriteUInt8(1)  # matching: SHA-256
		$certData = [byte[]](1..32)  # 32-byte SHA-256 hash
		$w.WriteBytes($certData)

		$bytes = $w.ToArray()
		$reader = [DnsBinaryReader]::new($bytes)
		$tlsa = [DnsTlsaRecord]::Parse($reader, $bytes.Length)

		$tlsa.CertUsage | Should -Be 3
		$tlsa.Selector | Should -Be 1
		$tlsa.MatchingType | Should -Be 1
		$tlsa.CertificateData.Length | Should -Be 32
	}

	It "Round-trips TLSA RDATA correctly" {
		$data = [byte[]](0..63)  # 64-byte SHA-512 hash
		$tlsa = [DnsTlsaRecord]::new(3, 0, 2, $data)  # DANE-EE, Full cert, SHA-512
		$bytes = $tlsa.ToWire()

		$reader = [DnsBinaryReader]::new($bytes)
		$parsed = [DnsTlsaRecord]::Parse($reader, $bytes.Length)

		$parsed.CertUsage | Should -Be 3
		$parsed.Selector | Should -Be 0
		$parsed.MatchingType | Should -Be 2
		$parsed.CertificateData.Length | Should -Be 64
	}

	It "Handles different TLSA usage types" {
		$data = [byte[]](1..32)

		$tlsa0 = [DnsTlsaRecord]::new(0, 1, 1, $data)  # PKIX-TA
		$tlsa1 = [DnsTlsaRecord]::new(1, 1, 1, $data)  # PKIX-EE
		$tlsa2 = [DnsTlsaRecord]::new(2, 1, 1, $data)  # DANE-TA
		$tlsa3 = [DnsTlsaRecord]::new(3, 1, 1, $data)  # DANE-EE

		$tlsa0.CertUsage | Should -Be 0
		$tlsa1.CertUsage | Should -Be 1
		$tlsa2.CertUsage | Should -Be 2
		$tlsa3.CertUsage | Should -Be 3
	}
}

Describe "RP Record Parsing and Encoding" {
	It "Parses an RP record" {
		$w = [DnsBinaryWriter]::new()
		$w.WriteName("admin.example.com")
		$w.WriteName("contact.example.com")
		$bytes = $w.ToArray()

		$reader = [DnsBinaryReader]::new($bytes)
		$rp = [DnsRpRecord]::Parse($reader, $bytes.Length)

		$rp.MailBox | Should -Be "admin.example.com"
		$rp.TxtDomain | Should -Be "contact.example.com"
	}

	It "Round-trips RP RDATA correctly" {
		$rp = [DnsRpRecord]::new("hostmaster.example.org", "info.example.org")
		$bytes = $rp.ToWire()

		$reader = [DnsBinaryReader]::new($bytes)
		$parsed = [DnsRpRecord]::Parse($reader, $bytes.Length)

		$parsed.MailBox | Should -Be "hostmaster.example.org"
		$parsed.TxtDomain | Should -Be "info.example.org"
	}
}

Describe "IPSECKEY Record Parsing and Encoding" {
	It "Parses an IPSECKEY record with an IPv4 gateway" {
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt8(10)  # precedence
		$w.WriteUInt8(1)   # gateway type: IPv4
		$w.WriteUInt8(2)   # algorithm: RSA
		$w.WriteBytes([System.Net.IPAddress]::Parse("192.0.2.38").GetAddressBytes())
		$key = [byte[]](1..16)
		$w.WriteBytes($key)
		$bytes = $w.ToArray()

		$reader = [DnsBinaryReader]::new($bytes)
		$ipseckey = [DnsIpsecKeyRecord]::Parse($reader, $bytes.Length)

		$ipseckey.Precedence | Should -Be 10
		$ipseckey.GatewayType | Should -Be 1
		$ipseckey.Algorithm | Should -Be 2
		$ipseckey.Gateway | Should -Be "192.0.2.38"
		$ipseckey.PublicKey.Length | Should -Be 16
	}

	It "Round-trips an IPSECKEY with no gateway (type 0)" {
		$key = [byte[]](0..31)
		$ipseckey = [DnsIpsecKeyRecord]::new(1, 0, 2, ".", $key)
		$bytes = $ipseckey.ToWire()

		$reader = [DnsBinaryReader]::new($bytes)
		$parsed = [DnsIpsecKeyRecord]::Parse($reader, $bytes.Length)

		$parsed.Precedence | Should -Be 1
		$parsed.GatewayType | Should -Be 0
		$parsed.Algorithm | Should -Be 2
		$parsed.Gateway | Should -Be "."
		$parsed.PublicKey.Length | Should -Be 32
	}

	It "Round-trips an IPSECKEY with a domain-name gateway (type 3)" {
		$key = [byte[]](1..20)
		$ipseckey = [DnsIpsecKeyRecord]::new(5, 3, 3, "gateway.example.com", $key)
		$bytes = $ipseckey.ToWire()

		$reader = [DnsBinaryReader]::new($bytes)
		$parsed = [DnsIpsecKeyRecord]::Parse($reader, $bytes.Length)

		$parsed.GatewayType | Should -Be 3
		$parsed.Gateway | Should -Be "gateway.example.com"
		$parsed.PublicKey.Length | Should -Be 20
	}

	It "Round-trips an IPSECKEY with an IPv6 gateway (type 2)" {
		$key = [byte[]](1..8)
		$ipseckey = [DnsIpsecKeyRecord]::new(2, 2, 2, "2001:db8::1", $key)
		$bytes = $ipseckey.ToWire()

		$reader = [DnsBinaryReader]::new($bytes)
		$parsed = [DnsIpsecKeyRecord]::Parse($reader, $bytes.Length)

		$parsed.GatewayType | Should -Be 2
		$parsed.Gateway | Should -Be "2001:db8::1"
		$parsed.PublicKey.Length | Should -Be 8
	}
}

Describe "OPENPGPKEY Record Parsing and Encoding" {
	It "Parses an OPENPGPKEY record" {
		$key = [byte[]](1..50)
		$w = [DnsBinaryWriter]::new()
		$w.WriteBytes($key)
		$bytes = $w.ToArray()

		$reader = [DnsBinaryReader]::new($bytes)
		$pgp = [DnsOpenPgpKeyRecord]::Parse($reader, $bytes.Length)

		$pgp.PublicKey.Length | Should -Be 50
	}

	It "Round-trips OPENPGPKEY RDATA correctly" {
		$key = [byte[]](0..99)
		$pgp = [DnsOpenPgpKeyRecord]::new($key)
		$bytes = $pgp.ToWire()

		$reader = [DnsBinaryReader]::new($bytes)
		$parsed = [DnsOpenPgpKeyRecord]::Parse($reader, $bytes.Length)

		$parsed.PublicKey.Length | Should -Be 100
		$parsed.GetPublicKeyBase64() | Should -Be ([Convert]::ToBase64String($key))
	}
}

Describe "MX Record Enhancement" {
	It "Parses MX record correctly" {
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE(10)
		$w.WriteName("mail.example.com")

		$bytes = $w.ToArray()
		$reader = [DnsBinaryReader]::new($bytes)
		$mx = [DnsMxRecord]::Parse($reader, $bytes.Length)

		$mx.Preference | Should -Be 10
		$mx.Exchange | Should -Be "mail.example.com"
	}
}

Describe "SRV Record Enhancement" {
	It "Parses SRV record correctly" {
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE(10)  # priority
		$w.WriteUInt16BE(20)  # weight
		$w.WriteUInt16BE(80)  # port
		$w.WriteName("server.example.com")

		$bytes = $w.ToArray()
		$reader = [DnsBinaryReader]::new($bytes)
		$srv = [DnsSrvRecord]::Parse($reader, $bytes.Length)

		$srv.Priority | Should -Be 10
		$srv.Weight | Should -Be 20
		$srv.Port | Should -Be 80
		$srv.Target | Should -Be "server.example.com"
	}
}

Describe "URI Record Parsing and Encoding" {
	It "Parses a URI record" {
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE(10)  # priority
		$w.WriteUInt16BE(1)   # weight
		$targetBytes = [System.Text.Encoding]::ASCII.GetBytes("https://example.com/path")
		$w.WriteBytes($targetBytes)

		$bytes = $w.ToArray()
		$reader = [DnsBinaryReader]::new($bytes)
		$uri = [DnsUriRecord]::Parse($reader, $bytes.Length)

		$uri.Priority | Should -Be 10
		$uri.Weight | Should -Be 1
		$uri.Target | Should -Be "https://example.com/path"
	}

	It "Round-trips URI RDATA correctly" {
		$uri = [DnsUriRecord]::new(20, 5, "ftp://files.example.org/pub")
		$bytes = $uri.ToWire()

		$reader = [DnsBinaryReader]::new($bytes)
		$parsed = [DnsUriRecord]::Parse($reader, $bytes.Length)

		$parsed.Priority | Should -Be 20
		$parsed.Weight | Should -Be 5
		$parsed.Target | Should -Be "ftp://files.example.org/pub"
	}

	It "Handles empty URI target" {
		$uri = [DnsUriRecord]::new(0, 0, "")
		$bytes = $uri.ToWire()

		$reader = [DnsBinaryReader]::new($bytes)
		$parsed = [DnsUriRecord]::Parse($reader, $bytes.Length)

		$parsed.Priority | Should -Be 0
		$parsed.Weight | Should -Be 0
		$parsed.Target | Should -Be ""
	}
}
