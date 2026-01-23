using module DnsTools

Describe 'Bootstrap Resolver' {

    Write-Host "### TEST FILE EXECUTED: $(Get-Date)" -ForegroundColor Green

    It 'Resolves NS names using glue' {
        $bytes = Get-Content "$PSScriptRoot/Fixtures/referral-with-glue.bin" -AsByteStream

        Mock Invoke-DnsUdpQuery {
            Write-Host "### MOCK HIT" -ForegroundColor Yellow
            return [byte[]]$bytes
        } -ModuleName DnsTools

        $ips = Resolve-NameserverAddress -NsName 'ns1.example.net' -BootstrapServers @('192.0.2.1')
        $ips | Should -Contain '192.0.2.53'
    }

    It 'Resolves NS names without glue by recursion' {
        $bytes1 = Get-Content "$PSScriptRoot/Fixtures/referral-no-glue.bin" -AsByteStream
        $bytes2 = Get-Content "$PSScriptRoot/Fixtures/referral-with-glue.bin" -AsByteStream

        $call = 0

        Mock Invoke-DnsUdpQuery {
            Write-Host "### MOCK HIT" -ForegroundColor Yellow
            if ($call++ -eq 0) { return [byte[]]$bytes1 }
            else { return [byte[]]$bytes2 }
        } -ModuleName DnsTools

        $ips = Resolve-NameserverAddress -NsName 'ns1.deep.example' -BootstrapServers @('192.0.2.1')
        $ips | Should -Contain '192.0.2.53'
    }
}
