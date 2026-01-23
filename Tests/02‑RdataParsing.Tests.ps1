using module DnsTools

Describe "RDATA Parsing" {

    It "Parses A record" {
        $r = [DnsARecord]::Parse([byte[]](192,168,1,10))
        $r.Address | Should -Be "192.168.1.10"
    }

    It "Parses AAAA record" {
        $bytes = [System.Net.IPAddress]::Parse("2001:db8::1").GetAddressBytes()
        $r = [DnsAaaaRecord]::Parse($bytes)
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
