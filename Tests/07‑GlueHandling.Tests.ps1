using module DnsTools
Describe "Glue Handling" {

    It "Prefers glue over NS recursion" {
        $bytes = Get-Content "$pSScriptRoot/Fixtures/referral-with-glue.bin" -AsByteStream
        Mock Invoke-DnsUdpQuery { return $bytes }

        $resp = Resolve-DnsIterative -Name "foo.example" -Type 1 -RootServers @("192.0.2.1")
        $resp.Reason | Should -Match "Answer found"
    }
}
