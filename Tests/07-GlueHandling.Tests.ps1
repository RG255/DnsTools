using module dnstools
Describe "Glue Handling" {

	It "Prefers glue over NS recursion" {
		$referral = [System.IO.File]::ReadAllBytes("$PSScriptRoot/Fixtures/referral-with-glue.bin")
		$answer = [System.IO.File]::ReadAllBytes("$PSScriptRoot/Fixtures/simple-a-record.bin")

		$script:call = 0
		Mock Invoke-DnsUdpQuery {
			switch ($script:call++) {
				0 { return $referral }
				default { return $answer }
			}
		} -ModuleName DnsTools

		$resp = Resolve-DnsIterative -Name "www.example.com" -Type 1 -RootServers @("192.0.2.1") -Raw
		$resp.Status | Should -Be "Final"
		$resp.Reason | Should -Match "Answer found"
	}
}
