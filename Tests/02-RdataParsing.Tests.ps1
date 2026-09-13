using module dnstools

Describe "RDATA Parsing" {

	It "Parses A record" {
		$bytes = [byte[]](192,168,1,10)
		$reader = [DnsBinaryReader]::new($bytes)

		$r = [DnsARecord]::Parse($reader, $bytes.Length)

		$r.Address | Should -Be "192.168.1.10"
	}

	It "Parses AAAA record" {
		$bytes = [System.Net.IPAddress]::Parse("2001:db8::1").GetAddressBytes()
		$reader = [DnsBinaryReader]::new($bytes)

		$r = [DnsAaaaRecord]::Parse($reader, $bytes.Length)

		$r.Address | Should -Be "2001:db8::1"
	}

	It "Parses CNAME record" {
		$r = [DnsCnameRecord]::new("target.example.com")
		$r.Target | Should -Be "target.example.com"
	}

	It "Parses NS record" {
		$ns = [DnsNsRecord]::new("ns1.example.com")
		$ns.NsName | Should -Be "ns1.example.com"
	}
}
