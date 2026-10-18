# Tests/27-AlgorithmsAndDenialProofs.Tests.ps1
# 0.8: RSA/SHA-1, RSA/SHA-512 and ECDSA P-384 verification, the NSEC3 next-closer derivation, and the proof that a
# delegation has no DS (insecure delegation) from signed NSEC / NSEC3 records.

using module dnstools

InModuleScope DnsTools {

	Describe "DNSSEC algorithms and denial proofs" {

		BeforeAll {
			function Get-TestRsaDnskey {
				param([int]$Algorithm)
				$rsa = [System.Security.Cryptography.RSA]::Create(2048)
				$p = $rsa.ExportParameters($false)
				$pub = [byte[]]@($p.Exponent.Length) + $p.Exponent + $p.Modulus
				[pscustomobject]@{ Key = $rsa; Dnskey = [DnsDnskeyRecord]::new(256, 3, $Algorithm, $pub) }
			}

			function Get-TestRrsig {
				param([int]$Algorithm, [byte[]]$Signature)
				$now = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
				[DnsRrsigRecord]::new(1, $Algorithm, 2, 300, ($now + 3600), ($now - 3600), 1, 'example.com', $Signature)
			}

			function Get-TestEcKey {
				$curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
				$ecdsa = [System.Security.Cryptography.ECDsa]::Create($curve)
				$p = $ecdsa.ExportParameters($false)
				$pub = [byte[]]($p.Q.X + $p.Q.Y)
				$dnskey = [DnsDnskeyRecord]::new(256, 3, 13, $pub)
				[pscustomobject]@{ Ecdsa = $ecdsa; Dnskey = $dnskey; Rr = [DnsResourceRecord]::new('example.com', 48, 1, 3600, $pub, $dnskey) }
			}

			function Get-SignedRr {
				# Signs ONE record (its own RRset) with the zone key.
				param($Key, $Rr, [string]$Signer = 'example.com')
				$now = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
				$stub = [DnsRrsigRecord]::new([uint16]$Rr.Type, 13, 3, 300, ($now + 3600), ($now - 3600), $Key.Dnskey.KeyTag, $Signer, [byte[]]@())
				$data = Get-DnssecSignedData -Rrsig $stub -Rrset @($Rr)
				$sig = $Key.Ecdsa.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
				$rrsig = [DnsRrsigRecord]::new([uint16]$Rr.Type, 13, 3, 300, ($now + 3600), ($now - 3600), $Key.Dnskey.KeyTag, $Signer, $sig)
				[DnsResourceRecord]::new($Rr.Name, 46, 1, 300, [byte[]]@(), $rrsig)
			}

			function Get-DenialResponse {
				param([object[]]$Authority)
				$p = [DnsPacket]::new()
				$p.Header = [DnsHeader]::new(1, 0x8400, 1, 0, [uint16]$Authority.Count, 0)
				foreach ($a in $Authority) { $null = $p.Authority.Add($a) }
				$p
			}
		}

		BeforeEach {
			Mock Write-MyCatchAudit { }
		}

		Context "Signature algorithms" {

			It "verifies RSA/SHA-512 (alg 10) and rejects tampered data" {
				$k = Get-TestRsaDnskey -Algorithm 10
				$data = [byte[]](1..40)
				$sig = $k.Key.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA512, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
				$rrsig = Get-TestRrsig -Algorithm 10 -Signature $sig
				Test-DnssecSignature -SignedData $data -Rrsig $rrsig -Dnskey $k.Dnskey | Should -BeTrue
				Test-DnssecSignature -SignedData ([byte[]](2..41)) -Rrsig $rrsig -Dnskey $k.Dnskey | Should -BeFalse
			}

			It "verifies RSA/SHA-1 (alg 5 and 7)" {
				foreach ($alg in 5, 7) {
					$k = Get-TestRsaDnskey -Algorithm $alg
					$data = [byte[]](1..40)
					$sig = $k.Key.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA1, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
					Test-DnssecSignature -SignedData $data -Rrsig (Get-TestRrsig -Algorithm $alg -Signature $sig) -Dnskey $k.Dnskey | Should -BeTrue
				}
			}

			It "verifies ECDSA P-384 (alg 14) and rejects tampered data" {
				$curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP384')
				$ecdsa = [System.Security.Cryptography.ECDsa]::Create($curve)
				$p = $ecdsa.ExportParameters($false)
				$dnskey = [DnsDnskeyRecord]::new(256, 3, 14, [byte[]]($p.Q.X + $p.Q.Y))
				$data = [byte[]](1..40)
				$sig = $ecdsa.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA384)
				$rrsig = Get-TestRrsig -Algorithm 14 -Signature $sig
				Test-DnssecSignature -SignedData $data -Rrsig $rrsig -Dnskey $dnskey | Should -BeTrue
				Test-DnssecSignature -SignedData ([byte[]](2..41)) -Rrsig $rrsig -Dnskey $dnskey | Should -BeFalse
			}

			It "throws for an unsupported algorithm instead of returning success" {
				$dnskey = [DnsDnskeyRecord]::new(256, 3, 15, [byte[]](1..32))
				{ Test-DnssecSignature -SignedData ([byte[]](1..4)) -Rrsig (Get-TestRrsig -Algorithm 15 -Signature ([byte[]](1..64))) -Dnskey $dnskey } | Should -Throw '*Unsupported*'
			}

			It "throws for a malformed RSA key" {
				$dnskey = [DnsDnskeyRecord]::new(256, 3, 8, [byte[]](200, 1, 2))
				{ Test-DnssecSignature -SignedData ([byte[]](1..4)) -Rrsig (Get-TestRrsig -Algorithm 8 -Signature ([byte[]](1..64))) -Dnskey $dnskey } | Should -Throw
			}
		}

		Context "Empty arrays from Parse" {

			It "parses an NSEC3 with an empty salt to an empty array, not null" {
				$rdata = [byte[]]@(1, 0, 0, 0, 0, 20) + [byte[]](1..20) + [byte[]](0, 1, 0x60)
				$r = [DnsBinaryReader]::new($rdata)
				$n3 = [DnsNsec3Record]::Parse($r, $rdata.Length, 'AAAAAAAA.example.com')
				$null -eq $n3.Salt | Should -BeFalse
				$n3.Salt.Length | Should -Be 0
			}

			It "parses zero-length RDATA to an empty RawRData, not null" {
				# name (root) + type 999 (unknown, so no typed parse) + class 1 + ttl 0 + rdlength 0
				$bytes = [byte[]](0, 3, 231, 0, 1, 0, 0, 0, 0, 0, 0)
				$rr = [DnsResourceRecord]::Parse([DnsBinaryReader]::new($bytes))
				$null -eq $rr.RawRData | Should -BeFalse
				$rr.RawRData.Length | Should -Be 0
			}
		}

		Context "NSEC3 next closer" {

			It "hashes the name one label below the closest encloser, not the query name" {
				$script:hashed = New-Object System.Collections.Generic.List[string]
				Mock Get-DnssecNsec3Hash {
					$script:hashed.Add($name)
					[byte[]](1..20)
				}
				$rec = [DnsNsec3Record]::new(1, 0, 0, [byte[]]@(), [byte[]](0..19), [byte[]](30..49), [int[]]@())
				$null = Find-DnssecNsec3NextCloser -QueryName 'x.y.z.example.com' -ClosestEncloserName 'z.example.com' -Nsec3Records @($rec) -HashAlgorithm 1 -Iterations 0 -salt ([byte[]]@())
				$script:hashed[0] | Should -Be 'y.z.example.com.'
			}

			It "returns null when the query is not below the closest encloser" {
				$rec = [DnsNsec3Record]::new(1, 0, 0, [byte[]]@(), [byte[]](0..19), [byte[]](30..49), [int[]]@())
				Find-DnssecNsec3NextCloser -QueryName 'z.example.com' -ClosestEncloserName 'z.example.com' -Nsec3Records @($rec) -HashAlgorithm 1 -Iterations 0 -salt ([byte[]]@()) | Should -BeNullOrEmpty
			}
		}

		Context "Test-DnssecDsAbsence" {

			It "proves an insecure delegation from a signed NSEC (NS, no DS)" {
				$k = Get-TestEcKey
				$n = [DnsNsecRecord]::new('next.example.com', [int[]](2, 46, 47))
				$nsec = [DnsResourceRecord]::new('child.example.com', 47, 1, 300, $n.ToWire(), $n)
				$resp = Get-DenialResponse -Authority @($nsec, (Get-SignedRr -Key $k -Rr $nsec))
				(Test-DnssecDsAbsence -Zone 'child.example.com' -ParentZone 'example.com' -ParentKeys @($k.Rr) -Response $resp).Proven | Should -BeTrue
			}

			It "does not accept an NSEC whose bitmap contains DS" {
				$k = Get-TestEcKey
				$n = [DnsNsecRecord]::new('next.example.com', [int[]](2, 43, 46, 47))
				$nsec = [DnsResourceRecord]::new('child.example.com', 47, 1, 300, $n.ToWire(), $n)
				$resp = Get-DenialResponse -Authority @($nsec, (Get-SignedRr -Key $k -Rr $nsec))
				(Test-DnssecDsAbsence -Zone 'child.example.com' -ParentZone 'example.com' -ParentKeys @($k.Rr) -Response $resp).Proven | Should -BeFalse
			}

			It "does not accept an unsigned NSEC (a stripped DS must not read as unsigned)" {
				$k = Get-TestEcKey
				$n = [DnsNsecRecord]::new('next.example.com', [int[]](2, 46, 47))
				$nsec = [DnsResourceRecord]::new('child.example.com', 47, 1, 300, $n.ToWire(), $n)
				$resp = Get-DenialResponse -Authority @($nsec)
				(Test-DnssecDsAbsence -Zone 'child.example.com' -ParentZone 'example.com' -ParentKeys @($k.Rr) -Response $resp).Proven | Should -BeFalse
			}

			It "does not accept an NSEC signed by a key the parent does not have" {
				$k = Get-TestEcKey
				$other = Get-TestEcKey
				$n = [DnsNsecRecord]::new('next.example.com', [int[]](2, 46, 47))
				$nsec = [DnsResourceRecord]::new('child.example.com', 47, 1, 300, $n.ToWire(), $n)
				$resp = Get-DenialResponse -Authority @($nsec, (Get-SignedRr -Key $other -Rr $nsec))
				(Test-DnssecDsAbsence -Zone 'child.example.com' -ParentZone 'example.com' -ParentKeys @($k.Rr) -Response $resp).Proven | Should -BeFalse
			}

			It "proves an insecure delegation from a signed matching NSEC3 with an empty salt" {
				$k = Get-TestEcKey
				$hash = Get-DnssecNsec3Hash -name 'child.example.com.' -Algorithm 1 -Iterations 0 -salt ([byte[]]@())
				$n3 = [DnsNsec3Record]::new(1, 0, 0, [byte[]]@(), $hash, [byte[]](1..20), [int[]](2, 46))
				$rr = [DnsResourceRecord]::new('abcdefgh.example.com', 50, 1, 300, $n3.ToWire(), $n3)
				$resp = Get-DenialResponse -Authority @($rr, (Get-SignedRr -Key $k -Rr $rr))
				(Test-DnssecDsAbsence -Zone 'child.example.com' -ParentZone 'example.com' -ParentKeys @($k.Rr) -Response $resp).Proven | Should -BeTrue
			}

			It "does not accept a matching NSEC3 whose bitmap contains DS" {
				$k = Get-TestEcKey
				$hash = Get-DnssecNsec3Hash -name 'child.example.com.' -Algorithm 1 -Iterations 0 -salt ([byte[]]@())
				$n3 = [DnsNsec3Record]::new(1, 0, 0, [byte[]]@(), $hash, [byte[]](1..20), [int[]](2, 43, 46))
				$rr = [DnsResourceRecord]::new('abcdefgh.example.com', 50, 1, 300, $n3.ToWire(), $n3)
				$resp = Get-DenialResponse -Authority @($rr, (Get-SignedRr -Key $k -Rr $rr))
				(Test-DnssecDsAbsence -Zone 'child.example.com' -ParentZone 'example.com' -ParentKeys @($k.Rr) -Response $resp).Proven | Should -BeFalse
			}
		}
	}
}
