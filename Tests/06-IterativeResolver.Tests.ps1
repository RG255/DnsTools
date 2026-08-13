#requires -Version 7.0
# PS7 ONLY: this suite uses Get-Content -AsByteStream, which does not exist in Windows
# PowerShell 5.1 (its equivalent is -Encoding Byte). Without this #requires, a powershell.exe
# run reported these as SEVEN FAILING TESTS that read like DNSSEC/parsing defects - the module
# is fine, the HOST was wrong. Under pwsh the same suites are 116/0. Declaring the requirement
# makes PowerShell skip them with a clear reason instead of failing misleadingly.
using module dnstools
Describe "Iterative Resolver" {

    It "Follows root → TLD → zone → answer" {
        $root = Get-Content "$PSScriptRoot/Fixtures/test06-root-referral.bin" -AsByteStream
        $tld  = Get-Content "$PSScriptRoot/Fixtures/test06-tld-referral.bin" -AsByteStream
        $auth = Get-Content "$PSScriptRoot/Fixtures/simple-a-record.bin" -AsByteStream

        $script:call = 0
        Mock Invoke-DnsUdpQuery {
            switch ($script:call++) {
                0 { return $root }
                1 { return $tld }
                2 { return $auth }
            }
        } -ModuleName DnsTools

        $resp = Resolve-DnsIterative -Name "www.example.com" -Type 1 -RootServers @("192.0.2.1") -Raw
        $resp.Status | Should -Be "Final"
        $resp.Response.Answers[0].RDataObject.Address | Should -Be "192.0.2.123"
    }
}
