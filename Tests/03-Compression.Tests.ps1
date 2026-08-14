using module dnstools

Describe "DNS Name Compression" {

    It "Decodes compressed names correctly" {
        $bytes = [System.IO.File]::ReadAllBytes("$PSScriptRoot/Fixtures/compressed-name.bin")
        $pkt = ConvertFrom-DnsPacket -Packet $bytes
        $pkt.Answers[0].Name | Should -Be "www.example.com"
    }

    It "Detects compression loops" {
        $bad = [byte[]](3, 97, 97, 97, 192, 0) # 'aaa' + pointer to offset 0
        $r = [DnsBinaryReader]::new($bad)
        { $r.ReadName() } | Should -Throw
    }
}
