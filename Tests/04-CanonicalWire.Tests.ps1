using module dnstools

Describe "Canonical Wire Format" {

    It "Lowercases owner names" {
        $rr = [DnsResourceRecord]::new("WWW.Example.COM", 1, 1, 3600, @(1,2,3,4), $null)
        $wire = $rr.ToCanonicalWire()
        $wire[0] | Should -Be 3  # length of 'www'
        $wire[1..3] | ForEach-Object { $_ } | Should -Be @(119,119,119)
    }

    It "Preserves RDATA bytes exactly" {
        $raw = @(1,2,3,4)
        $rr = [DnsResourceRecord]::new("a.example", 1, 1, 3600, $raw, $null)
        $wire = $rr.ToCanonicalWire()
        $wire[-4..-1] | Should -Be $raw
    }
}
