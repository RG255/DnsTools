#requires -Version 7.0
# PS7 ONLY: this suite uses Get-Content -AsByteStream, which does not exist in Windows
# PowerShell 5.1 (its equivalent is -Encoding Byte). Without this #requires, a powershell.exe
# run reported these as SEVEN FAILING TESTS that read like DNSSEC/parsing defects - the module
# is fine, the HOST was wrong. Under pwsh the same suites are 116/0. Declaring the requirement
# makes PowerShell skip them with a clear reason instead of failing misleadingly.
using module dnstools

Describe "DNS Name Compression" {

    It "Decodes compressed names correctly" {
        $bytes = Get-Content "$PSScriptRoot/Fixtures/compressed-name.bin" -AsByteStream
        $pkt = ConvertFrom-DnsPacket -Packet $bytes
        $pkt.Answers[0].Name | Should -Be "www.example.com"
    }

    It "Detects compression loops" {
        $bad = [byte[]](3, 97, 97, 97, 192, 0) # 'aaa' + pointer to offset 0
        $r = [DnsBinaryReader]::new($bad)
        { $r.ReadName() } | Should -Throw
    }
}
