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
