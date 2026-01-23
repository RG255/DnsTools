
using module dnstools

# Tests/DnsSecTools.Tests.ps1
# Run with: Invoke-Pester
#
# IMPORTANT:
# using module must be the first real statement in the file.
using module 'D:\PowerShellScripts\RawDns\0.3\DnsSecTools.psd1'

# ------------------------------------------------------------
# DNSSEC Trust Anchor Setup
# ------------------------------------------------------------

Describe 'DnsSecTools Module' {

    BeforeAll {
        # Load the module under test
        Import-Module "$PSScriptRoot\..\DnsSecTools.psd1" -Force

        # Create a synthetic DNSKEY for testing
        $script:dnskey = [DnsDnskeyRecord]::new(
            257,
            3,
            8,
            [byte[]](1..32)
        )

        # Override trust anchors in the module's script scope
        $module = Get-Module DnsSecTools
        $module.SessionState.PSVariable.Set(
            'TrustAnchors',
            @{
                '.' = @{
                    KeyTag     = $script:dnskey.KeyTag
                    Algorithm  = $script:dnskey.Algorithm
                    DigestType = 2
                    DigestHex  = 'e06d44b80b8f1d21f0f3e0d1d9c1c5b56a2f0e9f0e3c2c5c5e2e0f0f0c5b5a5c'
                }
            }
        )
    }

    Context 'DNSKEY and DS digest logic' {

        It 'validates trust anchor DNSKEY correctly' {
            Test-DnssecAnchoredDnskey -Zone '.' -Dnskey $script:dnskey | Should -BeTrue
        }
    }
}

#Describe -Name 'DnsSecTools Module' -Fixture {

	Context -Name 'DNS binary encoding primitives' -Fixture {
		It -Name 'writes and reads UInt16 in network byte order' -Test {
			$w = [DnsBinaryWriter]::new()
			$w.WriteUInt16BE(0x1234)
			$bytes = $w.ToArray()

			$r = [DnsBinaryReader]::new($bytes)
			$r.ReadUInt16BE() | Should -Be -ActualValue 0x1234
		}

		It -Name 'writes and reads DNS names without compression' -Test {
			$w = [DnsBinaryWriter]::new()
			$w.WriteName('www.example.com')
			$bytes = $w.ToArray()

			$r = [DnsBinaryReader]::new($bytes)
			$r.ReadName() | Should -Be -ActualValue 'www.example.com'
		}
	}

	Context -Name 'RDATA parsing (realistic DNS objects)' -Fixture {
		It -Name 'parses an A record correctly' -Test {
			$raw = [byte[]](192, 0, 2, 1)
			$rec = [DnsARecord]::Parse($raw)
			$rec.Address | Should -Be -ActualValue '192.0.2.1'
		}

		It -Name 'parses an AAAA record correctly' -Test {
			$ip = [System.Net.IPAddress]::Parse('2001:db8::1')
			$rec = [DnsAaaaRecord]::Parse($ip.GetAddressBytes())
			$rec.Address | Should -Be -ActualValue '2001:db8::1'
		}

		It -Name 'parses TXT records with multiple strings' -Test {
			$w = [DnsBinaryWriter]::new()
			$w.WriteUInt8(3)
			$w.WriteBytes([Text.Encoding]::ASCII.GetBytes('v=1'))
			$w.WriteUInt8(4)
			$w.WriteBytes([Text.Encoding]::ASCII.GetBytes('test'))

			$txt = [DnsTxtRecord]::Parse($w.ToArray())
			$txt.Strings | Should -Be -ActualValue @('v=1', 'test')
		}
	}

	Context -Name 'DNSKEY and DS digest logic' -Fixture {
		It -Name 'computes SHA256 DS digest deterministically' -Test {
			$dnskey = [DnsDnskeyRecord]::new(
				257,
				3,
				8,
				[byte[]](1..32)
			)

			$digest = Get-DnssecKeyDigest `
			-OwnerName '.' `
			-Dnskey $dnskey `
			-DigestType 2

			$digest.Length | Should -Be -ActualValue 32
		}
		
		It -Name 'validates trust anchor DNSKEY correctly' -Test {
			Write-Host -Object "ANCHOR IN MODULE SCOPE: $($script:TrustAnchors['.'])"
			$dnskey = [DnsDnskeyRecord]::new(
				257,
				3,
				8,
				[byte[]](1..32)
			)

			Mock -CommandName Get-DnssecKeyDigestHex -MockWith {'e06d44b80b8f1d21f0f3e0d1d9c1c5b56a2f0e9f0e3c2c5c5e2e0f0f0c5b5a5c'}
			Write-Host -Object "DNSKEY KeyTag: $($dnskey.KeyTag)"
			Write-Host -Object "ANCHOR: $($script:TrustAnchors['.'] | Out-String)"
			Write-Host -Object "DIGEST: $(Get-DnssecKeyDigestHex -OwnerName '.' -Dnskey $dnskey -DigestType 2)"
					
			Test-DnssecAnchoredDnskey -Zone '.' -Dnskey $dnskey | Should -BeTrue
		}
	}
	exit
	Context -Name 'RRSIG time validation' -Fixture {
		It -Name 'accepts signatures inside validity window' -Test {
			$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

			$sig = [DnsRrsigRecord]::new(
				1,8,1,3600,
				$now + 1000,
				$now - 1000,
				12345,
				'example.com',
				[byte[]](1..64)
			)

			Test-DnssecTimeWindow -Rrsig $sig | Should -BeTrue
		}

		It -Name 'rejects expired signatures' -Test {
			$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

			$sig = [DnsRrsigRecord]::new(
				1,8,1,3600,
				$now - 10,
				$now - 1000,
				12345,
				'example.com',
				[byte[]](1..64)
			)

			Test-DnssecTimeWindow -Rrsig $sig | Should -BeFalse
		}
	}

	Context -Name 'Network isolation' -Fixture {
		It -Name 'does not perform real UDP queries during tests' -Test {
			Mock -CommandName Invoke-DnsUdpQuery -MockWith {throw 'Network access attempted'}

			{Resolve-NameserverAddress -NsName 'ns.example.com' -BootstrapServers @('192.0.2.1')} |
			Should -Not -Throw
		}
	}

