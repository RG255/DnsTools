using module DnsTools

InModuleScope DnsTools {

	Describe 'Bootstrap Resolver' {

		It 'Resolves NS names using glue' {
			$bytes = [System.IO.File]::ReadAllBytes("$PSScriptRoot/Fixtures/referral-with-glue.bin")

			Mock Invoke-DnsUdpQuery {
				return [byte[]]$bytes
			} -ModuleName DnsTools

			$ips = Resolve-NameserverAddress -NsName 'ns1.example.net' -BootstrapServers @('192.0.2.1') -UseGlueOnly
			$ips | Should -Contain '192.0.2.53'
		}

		It 'Resolves NS names without glue by recursion' {
			$bytes1 = [System.IO.File]::ReadAllBytes("$PSScriptRoot/Fixtures/referral-no-glue.bin")
			$bytes2 = [System.IO.File]::ReadAllBytes("$PSScriptRoot/Fixtures/referral-with-glue.bin")

			$script:call = 0

			Mock Invoke-DnsUdpQuery {
				if ($script:call++ -eq 0) { return [byte[]]$bytes1 }
				else { return [byte[]]$bytes2 }
			} -ModuleName DnsTools

			$ips = Resolve-NameserverAddress -NsName 'ns1.deep.example' -BootstrapServers @('192.0.2.1') -UseGlueOnly
			$ips | Should -Contain '192.0.2.53'
		}
	}
}
