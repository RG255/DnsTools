using module dnstools

Describe "NSEC3 NXDOMAIN Proof" {

    BeforeAll {
        $algo = 1
        $iter = 5
        $salt = [byte[]](0x12,0x34)

        function _TestHash {
            param([string]$Name)
            $canon = $Name.ToLower().TrimEnd('.') + '.'
            Get-DnssecNsec3Hash -Name $canon -Algorithm $algo -Iterations $iter -Salt $salt
        }

        # Precompute hashes
        $hash_example = _TestHash 'example.com'
        $hash_b       = _TestHash 'b.example.com'
        $hash_a_b     = _TestHash 'a.b.example.com'

        # Build NSEC3 records
        # example.com → b.example.com
        $nsec3_example = [DnsNsec3Record]::new(
            $algo,0,$iter,$salt,
            $hash_example,
            $hash_b,
            [int[]]@()
        )

        # b.example.com → example.com (wrap interval)
        $nsec3_b = [DnsNsec3Record]::new(
            $algo,0,$iter,$salt,
            $hash_b,
            $hash_example,
            [int[]]@()
        )

        $records = @($nsec3_example, $nsec3_b)
    }

    It "Proves NXDOMAIN when CE and NC both succeed" {
        $result = Test-DnssecNsec3Nxdomain `
                    -QueryName 'a.b.example.com' `
                    -Nsec3Records $records `
                    -HashAlgorithm $algo `
                    -Iterations $iter `
                    -Salt $salt

        $result.Nxdomain | Should -BeTrue
        ($result.ClosestEncloser.Name) | Should -Be 'b.example.com'
        ($result.NextCloser.OwnerHash -join ',') | Should -Be ($hash_b -join ',')
    }

    It "Fails NXDOMAIN when CE fails" {
        $result = Test-DnssecNsec3Nxdomain `
                    -QueryName 'a.b.example.com' `
                    -Nsec3Records @() `
                    -HashAlgorithm $algo `
                    -Iterations $iter `
                    -Salt $salt

        $result.Nxdomain | Should -BeFalse
        $result.Reason   | Should -Be "No closest encloser found"
    }

    It "Fails NXDOMAIN when NC fails" {
        # CE will succeed, NC will fail because no interval covers the hash
        $result = Test-DnssecNsec3Nxdomain `
                    -QueryName 'a.b.example.com' `
                    -Nsec3Records @($nsec3_example) `
                    -HashAlgorithm $algo `
                    -Iterations $iter `
                    -Salt $salt

        $result.Nxdomain | Should -BeFalse
        $result.Reason   | Should -Be "No covering NSEC3 record for next-closer name"
    }
}
