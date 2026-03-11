using module dnstools

Describe "NSEC3 Next Closer" {

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

    It "Finds the covering NSEC3 record for next-closer name" {
        $result = Find-DnssecNsec3NextCloser `
                    -QueryName 'a.b.example.com' `
                    -ClosestEncloserName 'b.example.com' `
                    -Nsec3Records $records `
                    -HashAlgorithm $algo `
                    -Iterations $iter `
                    -Salt $salt

        $result | Should -Not -BeNullOrEmpty
        ($result.OwnerHash -join ',') | Should -Be ($hash_b -join ',')
    }

    It "Handles wrap-around intervals correctly" {
        $result = Find-DnssecNsec3NextCloser `
                    -QueryName 'a.b.example.com' `
                    -ClosestEncloserName 'b.example.com' `
                    -Nsec3Records $records `
                    -HashAlgorithm $algo `
                    -Iterations $iter `
                    -Salt $salt

        $result | Should -Not -BeNullOrEmpty
    }

    It "Returns null when no interval covers the next-closer hash" {
        # Cleanest possible test: no NSEC3 records → no coverage
        $result = Find-DnssecNsec3NextCloser `
                    -QueryName 'a.b.example.com' `
                    -ClosestEncloserName 'b.example.com' `
                    -Nsec3Records @() `
                    -HashAlgorithm $algo `
                    -Iterations $iter `
                    -Salt $salt

        $result | Should -BeNullOrEmpty
    }
}
