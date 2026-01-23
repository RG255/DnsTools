using module DnsTools
Describe "Iterative Resolver" {

    It "Follows root → TLD → zone → answer" {
        $root = Get-Content "$PSScriptRoot/Fixtures/referral-with-glue.bin" -AsByteStream
        $tld  = Get-Content "$pSScriptRoot/Fixtures/referral-with-glue.bin" -AsByteStream
        $auth = Get-Content "$pSScriptRoot/Fixtures/simple-a-record.bin" -AsByteStream

        $call = 0
        Mock Invoke-DnsUdpQuery {
            switch ($call++) {
                0 { return $root }
                1 { return $tld }
                2 { return $auth }
            }
        }

        $resp = Resolve-DnsIterative -Name "www.example.com" -Type 1 -RootServers @("192.0.2.1")
        $resp.Status | Should -Be "Final"
        $resp.Response.Answers[0].RDataObject.Address | Should -Be "192.0.2.123"
    }
}
