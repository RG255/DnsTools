using module DnsTools

InModuleScope DnsTools {

Describe 'Bootstrap Resolver' {

    It 'Resolves NS names using glue' {
        $bytes = Get-Content "$PSScriptRoot/Fixtures/referral-with-glue.bin" -AsByteStream

        Mock Invoke-DnsUdpQuery {
            return [byte[]]$bytes
        } -ModuleName DnsTools

        $ips = Resolve-NameserverAddress -NsName 'ns1.example.net' -BootstrapServers @('192.0.2.1') -UseGlueOnly
        $ips | Should -Contain '192.0.2.53'
    }

    It 'Resolves NS names without glue by recursion' {
        $bytes1 = Get-Content "$PSScriptRoot/Fixtures/referral-no-glue.bin" -AsByteStream
        $bytes2 = Get-Content "$PSScriptRoot/Fixtures/referral-with-glue.bin" -AsByteStream

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
