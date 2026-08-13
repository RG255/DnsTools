# Tests/13-DnssecCrypto.Tests.ps1
# DNSSEC Cryptographic Operations Tests

using module dnstools

InModuleScope DnsTools {
Describe "DNSSEC Cryptographic Functions" {

    #
    # Synthetic RSA and ECDSA keys for deterministic testing
    #
    BeforeAll {
        # RSA 2048-bit test key
        $script:TestRsa = [System.Security.Cryptography.RSA]::Create(2048)
        $rsaParams = $script:TestRsa.ExportParameters($false)

        # Convert to DNSKEY wire format: [exp_len][exponent][modulus]
        $expLen = $rsaParams.Exponent.Length
        if ($expLen -le 255) {
            $script:TestRsaPub = [byte[]]@($expLen) + $rsaParams.Exponent + $rsaParams.Modulus
        } else {
            $script:TestRsaPub = [byte[]]@(0, ($expLen -shr 8), ($expLen -band 0xFF)) + $rsaParams.Exponent + $rsaParams.Modulus
        }

        # ECDSA P-256 test key
        $curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
        $script:TestEcdsa = [System.Security.Cryptography.ECDsa]::Create($curve)
        $ecParams = $script:TestEcdsa.ExportParameters($false)

        # Convert to DNSKEY wire format: [X (32 bytes)][Y (32 bytes)]
        $script:TestEcdsaPub = $ecParams.Q.X + $ecParams.Q.Y
    }

    Context "KeyTag Computation" {

        It "Computes deterministic KeyTag for RSA key" {
            $dnskey = [DnsDnskeyRecord]::new(256, 3, 8, $Script:TestRsaPub)
            $dnskey.KeyTag | Should -BeGreaterThan 0
        }

        It "Computes deterministic KeyTag for ECDSA key" {
            $dnskey = [DnsDnskeyRecord]::new(256, 3, 13, $Script:TestEcdsaPub)
            $dnskey.KeyTag | Should -BeGreaterThan 0
        }
    }

    Context "DS Digest Generation" {

        It "Generates SHA-256 DS digest" {
            $dnskey = [DnsDnskeyRecord]::new(256, 3, 8, $Script:TestRsaPub)

            $digest = Get-DnssecKeyDigest -OwnerName "example.com" -Dnskey $dnskey -DigestType 2
            $digest.Length | Should -Be 32
        }

        It "Generates SHA-384 DS digest" {
            $dnskey = [DnsDnskeyRecord]::new(256, 3, 8, $Script:TestRsaPub)

            $digest = Get-DnssecKeyDigest -OwnerName "example.com" -Dnskey $dnskey -DigestType 4
            $digest.Length | Should -Be 48
        }
    }

    Context "Signature Verification" {

        It "Verifies RSA/SHA256 signature" {
            # Build synthetic signed data
            $data = [System.Text.Encoding]::ASCII.GetBytes("dnssec-test-data")

            # Sign with RSA
            $sig = $Script:TestRsa.SignData(
                $data,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )

            # Build DNSKEY
            $dnskey = [DnsDnskeyRecord]::new(256, 3, 8, $Script:TestRsaPub)

            # Build RRSIG
            $rrsig = [DnsRrsigRecord]::new(
                1, 8, 2, 300,
                999999999, 0,
                $dnskey.KeyTag,
                "example.com",
                $sig
            )

            $ok = Test-DnssecSignature -SignedData $data -Rrsig $rrsig -Dnskey $dnskey
            $ok | Should -BeTrue
        }

        It "Verifies ECDSA/SHA256 signature" {
            $data = [System.Text.Encoding]::ASCII.GetBytes("dnssec-ecdsa-test")

            $sig = $Script:TestEcdsa.SignData(
                $data,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256
            )

            $dnskey = [DnsDnskeyRecord]::new(256, 3, 13, $Script:TestEcdsaPub)

            $rrsig = [DnsRrsigRecord]::new(
                1, 13, 2, 300,
                999999999, 0,
                $dnskey.KeyTag,
                "example.com",
                $sig
            )

            $ok = Test-DnssecSignature -SignedData $data -Rrsig $rrsig -Dnskey $dnskey
            $ok | Should -BeTrue
        }
    }

    Context "Time Window Validation" {

        It "Accepts RRSIG inside validity window" {
            $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

            $rrsig = [DnsRrsigRecord]::new(
                1, 8, 2, 300,
                $now + 1000,
                $now - 1000,
                12345,
                "example.com",
                ([byte[]](1..32))
            )

            Test-DnssecTimeWindow -Rrsig $rrsig | Should -BeTrue
        }

        It "Rejects RRSIG before inception" {
            $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

            $rrsig = [DnsRrsigRecord]::new(
                1, 8, 2, 300,
                $now + 2000,
                $now + 1000,
                12345,
                "example.com",
                ([byte[]](1..32))
            )

            Test-DnssecTimeWindow -Rrsig $rrsig | Should -BeFalse
        }

        It "Rejects RRSIG after expiration" {
            $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

            $rrsig = [DnsRrsigRecord]::new(
                1, 8, 2, 300,
                $now - 1000,
                $now - 2000,
                12345,
                "example.com",
                ([byte[]](1..32))
            )

            Test-DnssecTimeWindow -Rrsig $rrsig | Should -BeFalse
        }
    }
}
}
