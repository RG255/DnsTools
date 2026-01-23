using module dnstools

using module dnstools

Describe "NSEC3 NODATA Proof" {

    BeforeAll {
        $algo = 1
        $iter = 5
        $salt = [byte[]](0x12,0x34)

        function _TestHash {
            param([string]$Name)
            $canon = $Name.ToLower().TrimEnd('.') + '.'
            Get-DnssecNsec3Hash -Name $canon -Algorithm $algo -Iterations $iter -Salt $salt
        }

        $hash_example = _TestHash 'example.com'
        $hash_b       = _TestHash 'b.example.com'

        $nsec3_example = [DnsNsec3Record]::new(
            $algo,0,$iter,$salt,
            $hash_example,
            $hash_b,
            [int[]]@(1, 2, 5)
        )

        $nsec3_b = [DnsNsec3Record]::new(
            $algo,0,$iter,$salt,
            $hash_b,
            $hash_example,
            [int[]]@(1, 5)
        )

        $records = @($nsec3_example, $nsec3_b)
    }

    It "Proves NODATA when name exists but type does not" {
        $result = Test-DnssecNsec3Nodata `
                    -QueryName 'b.example.com' `
                    -QueryType 28 `
                    -Nsec3Records $records `
                    -HashAlgorithm $algo `
                    -Iterations $iter `
                    -Salt $salt

        $result.Nodata | Should -BeTrue
        $result.ClosestEncloser.Name | Should -Be 'b.example.com'
    }

    It "Fails NODATA when CE is not the query name" {
        $result = Test-DnssecNsec3Nodata `
                    -QueryName 'a.b.example.com' `
                    -QueryType 28 `
                    -Nsec3Records $records `
                    -HashAlgorithm $algo `
                    -Iterations $iter `
                    -Salt $salt

        $result.Nodata | Should -BeFalse
        $result.Reason | Should -Be "Closest encloser is not the query name"
    }

    It "Fails NODATA when the requested type exists" {
        $result = Test-DnssecNsec3Nodata `
                    -QueryName 'b.example.com' `
                    -QueryType 1 `
                    -Nsec3Records $records `
                    -HashAlgorithm $algo `
                    -Iterations $iter `
                    -Salt $salt

        $result.Nodata | Should -BeFalse
        $result.Reason | Should -Be "Requested type exists"
    }
}
