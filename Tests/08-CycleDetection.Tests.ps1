#requires -Version 7.0
# PS7 ONLY: this suite uses Get-Content -AsByteStream, which does not exist in Windows
# PowerShell 5.1 (its equivalent is -Encoding Byte). Without this #requires, a powershell.exe
# run reported these as SEVEN FAILING TESTS that read like DNSSEC/parsing defects - the module
# is fine, the HOST was wrong. Under pwsh the same suites are 116/0. Declaring the requirement
# makes PowerShell skip them with a clear reason instead of failing misleadingly.
using module dnstools

Describe "Cycle Detection" {

    It "Detects server-set cycles" {
        Mock Invoke-DnsUdpQuery {
            return (Get-Content "$PSScriptRoot/Fixtures/referral-no-glue.bin" -AsByteStream)
        } -ModuleName DnsTools

        $resp = Resolve-DnsIterative -Name "loop.example" -Type 1 -RootServers @("192.0.2.1") -Raw
        $resp.Status | Should -Be "BailOut"
        $resp.Reason | Should -Match "cycle"
    }
}
