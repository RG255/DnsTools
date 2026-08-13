# Tests/12-DnssecCanonicalization.Tests.ps1
# DNSSEC Canonicalization Tests (RFC 4034)

using module dnstools

InModuleScope DnsTools {

Describe "DNSSEC Canonicalization Functions" {

    Context "Canonical Name Wire" {

        It "Produces lowercase, label-length-prefixed wire format" {
            $bytes = Get-DnssecCanonicalNameWire -Name "WWW.Example.COM"

            # Expected: 3 'www', 7 'example', 3 'com', 0 root
            $bytes[0]  | Should -Be 3
            $bytes[1..3]  | ForEach-Object { [char]$_ } | Should -Be @('w','w','w')

            $bytes[4]  | Should -Be 7
            $bytes[5..11] | ForEach-Object { [char]$_ } | Should -Be @('e','x','a','m','p','l','e')

            $bytes[12] | Should -Be 3
            $bytes[13..15] | ForEach-Object { [char]$_ } | Should -Be @('c','o','m')
            $bytes[16] | Should -Be 0
        }

        It "Matches canonical-name-wire.bin fixture" {
            $path = Join-Path $PSScriptRoot/Fixtures "canonical-name-wire.bin"
            $fixture = [IO.File]::ReadAllBytes($path)

            $bytes = Get-DnssecCanonicalNameWire -Name "www.Example.COM"

            $bytes | Should -Be $fixture
        }
    }

    Context "Canonical RR Wire" {

        It "Produces deterministic canonical RR wire" {
            $rr = [DnsResourceRecord]::new(
                "a.example",
                1,
                1,
                300,
                ([byte[]](1,2,3,4)),
                $null
            )

            $wire = Get-DnssecCanonicalRrWire -rr $rr

            # Owner name must be lowercase and uncompressed
            $wire[0] | Should -Be 1
            [char]$wire[1] | Should -Be 'a'
        }
    }

    Context "Canonical RRset Sorting" {

        It "Sorts RRset by RDATA lexicographically" {
            $rr1 = [DnsResourceRecord]::new("a.example", 1, 1, 300, ([byte[]](1,2,3,4)), $null)
            $rr2 = [DnsResourceRecord]::new("a.example", 1, 1, 300, ([byte[]](1,2,3,5)), $null)

            $sorted = Get-DnssecCanonicalRrsetData -Rrset @($rr2, $rr1)

            $sorted[0].RdataWire | Should -Be ([byte[]](1,2,3,4))
            $sorted[1].RdataWire | Should -Be ([byte[]](1,2,3,5))
        }

        It "Matches canonical-rrset.bin fixture" {
            $path = Join-Path $PSScriptRoot/Fixtures "canonical-rrset.bin"
            $fixture = [IO.File]::ReadAllBytes($path)

            $rr1 = [DnsResourceRecord]::new("a.example", 1, 1, 300, ([byte[]](1,2,3,4)), $null)
            $rr2 = [DnsResourceRecord]::new("a.example", 1, 1, 300, ([byte[]](1,2,3,5)), $null)

            $sorted = Get-DnssecCanonicalRrsetData -Rrset @($rr1, $rr2)

            $bytes = New-Object System.Collections.Generic.List[byte]
            foreach ($rec in $sorted) { $bytes.AddRange($rec.RdataWire) }

            $bytes.ToArray() | Should -Be $fixture
        }
    }

    Context "Signed Data Construction" {

        It "Builds deterministic signed-data for RRSIG + RRset" {
            $rr1 = [DnsResourceRecord]::new("a.example", 1, 1, 300, ([byte[]](1,2,3,4)), $null)
            $rr2 = [DnsResourceRecord]::new("a.example", 1, 1, 300, ([byte[]](1,2,3,5)), $null)

            $rrsig = [DnsRrsigRecord]::new(
                1,      # TypeCovered
                8,      # Algorithm
                2,      # Labels
                300,    # Original TTL
                1000,   # Expiration
                900,    # Inception
                12345,  # KeyTag
                "example.com",
                ([byte[]](1..32)) # Signature placeholder
            )

            $sd = Get-DnssecSignedData -Rrsig $rrsig -Rrset @($rr1, $rr2)

            $sd.Length | Should -BeGreaterThan 20
        }

        It "Matches signed-data.bin fixture" {
            $path = Join-Path $PSScriptRoot/Fixtures "signed-data.bin"
            $fixture = [IO.File]::ReadAllBytes($path)

            $rr1 = [DnsResourceRecord]::new("a.example", 1, 1, 300, ([byte[]](1,2,3,4)), $null)
            $rr2 = [DnsResourceRecord]::new("a.example", 1, 1, 300, ([byte[]](1,2,3,5)), $null)

            $rrsig = [DnsRrsigRecord]::new(
                1, 8, 2, 300, 1000, 900, 12345, "example.com", ([byte[]](1..32))
            )

            $sd = Get-DnssecSignedData -Rrsig $rrsig -Rrset @($rr1, $rr2)

            $sd | Should -Be $fixture
        }
    }
}
}
