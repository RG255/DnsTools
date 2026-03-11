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
