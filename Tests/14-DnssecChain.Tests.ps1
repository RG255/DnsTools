# Tests/14-DnssecChain.Tests.ps1
# DNSSEC Chain Validation Tests

using module dnstools

InModuleScope DnsTools {

Describe "DNSSEC Chain Validation" {

    BeforeAll {
        #
        # Build synthetic DNSKEY RRset
        #
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $rsaParams = $rsa.ExportParameters($false)

        # Convert to DNSKEY wire format: [exp_len][exponent][modulus]
        $expLen = $rsaParams.Exponent.Length
        if ($expLen -le 255) {
            $rsaPub = [byte[]]@($expLen) + $rsaParams.Exponent + $rsaParams.Modulus
        } else {
            $rsaPub = [byte[]]@(0, ($expLen -shr 8), ($expLen -band 0xFF)) + $rsaParams.Exponent + $rsaParams.Modulus
        }

        $dnskey = [DnsDnskeyRecord]::new(
            256, 3, 8, $rsaPub
        )

        $dnskeyRR = [DnsResourceRecord]::new(
            "example.com",
            48,
            1,
            3600,
            $dnskey.PublicKey,
            $dnskey
        )

        $script:TestDnskey = $dnskey
        $script:TestDnskeyRR = $dnskeyRR

        #
        # Build synthetic DS record
        #
        $digest = Get-DnssecKeyDigest -OwnerName "example.com" -Dnskey $dnskey -DigestType 2

        $ds = [DnsDsRecord]::new(
            $dnskey.KeyTag,
            $dnskey.Algorithm,
            2,
            $digest
        )

        $dsRR = [DnsResourceRecord]::new(
            "example.com",
            43,
            1,
            3600,
            $ds.Digest,
            $ds
        )

        $script:TestDs = $ds
        $script:TestDsRR = $dsRR

        #
        # Build synthetic RRSIG over DNSKEY RRset
        #
        $data = [System.Text.Encoding]::ASCII.GetBytes("dnssec-chain-test")

        $sig = $rsa.SignData(
            $data,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )

        $rrsig = [DnsRrsigRecord]::new(
            48,     # TypeCovered = DNSKEY
            8,      # RSA/SHA256
            1,      # Labels
            3600,   # Original TTL
            ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 3600),
            ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 3600),
            $dnskey.KeyTag,
            "example.com",
            $sig
        )

        $rrsigRR = [DnsResourceRecord]::new(
            "example.com",
            46,
            1,
            3600,
            $rrsig.Signature,
            $rrsig
        )

        $script:TestRrsig = $rrsig
        $script:TestRrsigRR = $rrsigRR

        #
        # Mock Get-DnssecSignedData to return deterministic data
        #
        Mock Get-DnssecSignedData { return $data } -ModuleName DnsTools
    }

    Context "DS → DNSKEY Matching" {

        It "Validates DS matches DNSKEY" {
            $result = Test-DnssecDsForDnskey `
                -DsRrset @($Script:TestDsRR) `
                -DnskeyRrset @($Script:TestDnskeyRR) `
                -ChildZoneName "example.com"

            $result[0].Valid | Should -BeTrue
        }

        It "Rejects DS with wrong digest" {
            $badDs = [DnsDsRecord]::new(
                $Script:TestDnskey.KeyTag,
                $Script:TestDnskey.Algorithm,
                2,
                ([byte[]](0..31))   # wrong digest
            )

            $badRR = [DnsResourceRecord]::new(
                "example.com",
                43,
                1,
                3600,
                $badDs.Digest,
                $badDs
            )

            $result = Test-DnssecDsForDnskey `
                -DsRrset @($badRR) `
                -DnskeyRrset @($Script:TestDnskeyRR) `
                -ChildZoneName "example.com"

            $result[0].Valid | Should -BeFalse
        }
    }

    Context "RRSIG → DNSKEY Matching" {

        It "Validates RRSIG matches DNSKEY" {
            $result = Test-DnssecRrsig `
                -Rrsig $Script:TestRrsig `
                -Rrset @($Script:TestDnskeyRR) `
                -DnskeyRrset @($Script:TestDnskeyRR)

            $result.Valid | Should -BeTrue
        }

        It "Rejects RRSIG with wrong key tag" {
            $badSig = [DnsRrsigRecord]::new(
                48, 8, 1, 3600,
                ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 3600),
                ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 3600),
                65000,  # wrong key tag
                "example.com",
                $Script:TestRrsig.Signature
            )

            $result = Test-DnssecRrsig `
                -Rrsig $badSig `
                -Rrset @($Script:TestDnskeyRR) `
                -DnskeyRrset @($Script:TestDnskeyRR)

            $result.Valid | Should -BeFalse
        }
    }

    Context "Full Chain Validation" {

        It "Validates full DNSSEC chain" {
            $result = Test-DnssecChain `
                -DnskeyRrset @($Script:TestDnskeyRR) `
                -DsRrset @($Script:TestDsRR) `
                -RrsigRrset @($Script:TestRrsigRR) `
                -ZoneName "example.com"

            $result.Valid | Should -BeTrue
        }

        It "Fails when DS does not match DNSKEY" {
            $badDs = [DnsDsRecord]::new(
                $Script:TestDnskey.KeyTag,
                $Script:TestDnskey.Algorithm,
                2,
                ([byte[]](0..31))
            )

            $badRR = [DnsResourceRecord]::new(
                "example.com",
                43,
                1,
                3600,
                $badDs.Digest,
                $badDs
            )

            $result = Test-DnssecChain `
                -DnskeyRrset @($Script:TestDnskeyRR) `
                -DsRrset @($badRR) `
                -RrsigRrset @($Script:TestRrsigRR) `
                -ZoneName "example.com"

            $result.Valid | Should -BeFalse
            $result.Reason | Should -Match "No DNSKEY matches DS"
        }

        It "Fails when RRSIG does not match DNSKEY" {
            $badSig = [DnsRrsigRecord]::new(
                48, 8, 1, 3600,
                ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 3600),
                ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 3600),
                65000,
                "example.com",
                $Script:TestRrsig.Signature
            )

            $badRR = [DnsResourceRecord]::new(
                "example.com",
                46,
                1,
                3600,
                $badSig.Signature,
                $badSig
            )

            $result = Test-DnssecChain `
                -DnskeyRrset @($Script:TestDnskeyRR) `
                -DsRrset @($Script:TestDsRR) `
                -RrsigRrset @($badRR) `
                -ZoneName "example.com"

            $result.Valid | Should -BeFalse
            $result.Reason | Should -Match "No matching DNSKEY for RRSIG"
        }
    }
}
}
