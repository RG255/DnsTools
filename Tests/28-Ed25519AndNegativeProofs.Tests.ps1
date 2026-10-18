# Tests/28-Ed25519AndNegativeProofs.Tests.ps1
# 0.8: the managed Ed25519 verifier (algorithm 15), canonical name ordering, and authenticated denial of existence
# (signed NXDOMAIN / NODATA answers) with NSEC and NSEC3.

using module dnstools

InModuleScope DnsTools {

	Describe "Ed25519, name ordering and negative-answer proofs" {

		BeforeAll {
			function ConvertFrom-TestHex {
				param([string]$Hex)
				[byte[]]($Hex -split '(?<=\G..)(?=.)' | ForEach-Object { [Convert]::ToByte($_, 16) })
			}

			function Get-TestZoneKey {
				$curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
				$ecdsa = [System.Security.Cryptography.ECDsa]::Create($curve)
				$p = $ecdsa.ExportParameters($false)
				$pub = [byte[]]($p.Q.X + $p.Q.Y)
				$dnskey = [DnsDnskeyRecord]::new(256, 3, 13, $pub)
				[pscustomobject]@{ Ecdsa = $ecdsa; Dnskey = $dnskey; Rr = [DnsResourceRecord]::new('example.com', 48, 1, 3600, $pub, $dnskey) }
			}

			function Get-SignedRr {
				param($Key, $Rr)
				$now = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
				$labels = @($Rr.Name.TrimEnd('.').Split('.')).Count
				$stub = [DnsRrsigRecord]::new([uint16]$Rr.Type, 13, [byte]$labels, 300, ($now + 3600), ($now - 3600), $Key.Dnskey.KeyTag, 'example.com', [byte[]]@())
				$data = Get-DnssecSignedData -Rrsig $stub -Rrset @($Rr)
				$sig = $Key.Ecdsa.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
				$rrsig = [DnsRrsigRecord]::new([uint16]$Rr.Type, 13, [byte]$labels, 300, ($now + 3600), ($now - 3600), $Key.Dnskey.KeyTag, 'example.com', $sig)
				[DnsResourceRecord]::new($Rr.Name, 46, 1, 300, [byte[]]@(), $rrsig)
			}

			function Get-SoaRr {
				$soa = [DnsSoaRecord]::new('ns.example.com', 'h.example.com', 1, 2, 3, 4, 5)
				[DnsResourceRecord]::new('example.com', 6, 1, 300, $soa.ToWire(), $soa)
			}

			function Get-NsecRr {
				param([string]$Owner, [string]$Next, [int[]]$Types)
				$n = [DnsNsecRecord]::new($Next, $Types)
				[DnsResourceRecord]::new($Owner, 47, 1, 300, $n.ToWire(), $n)
			}

			function Get-NegativeResponse {
				param([uint16]$Rcode, [object[]]$Authority)
				$p = [DnsPacket]::new()
				$p.Header = [DnsHeader]::new(1, [uint16](0x8400 -bor $Rcode), 1, 0, [uint16]$Authority.Count, 0)
				foreach ($a in $Authority) { $null = $p.Authority.Add($a) }
				$p
			}

			function Get-AdjustedHash {
				# hash +/- delta as a 20-byte big-endian array (to build an NSEC3 interval that covers a given hash)
				param([byte[]]$Hash, [int]$Delta)
				$flipped = [byte[]]($Hash.Clone()); [array]::Reverse($flipped)
				$bi = [System.Numerics.BigInteger]::new([byte[]]($flipped + [byte[]](0)))
				$bi = $bi + $Delta
				$le = $bi.ToByteArray()
				$out = New-Object byte[] 20
				for ($i = 0; $i -lt 20 -and $i -lt $le.Length; $i++) { $out[19 - $i] = $le[$i] }
				$out
			}
		}

		BeforeEach {
			Mock Write-MyCatchAudit { }
		}

		Context "Ed25519 verifier" {

			It "verifies RFC 8032 test vector 1 (empty message)" {
				Test-DnssecEd25519Signature -PublicKey (ConvertFrom-TestHex 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a') -Signature (ConvertFrom-TestHex 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b') -Message ([byte[]]@()) | Should -BeTrue
			}

			It "verifies RFC 8032 test vector 2 (one byte)" {
				Test-DnssecEd25519Signature -PublicKey (ConvertFrom-TestHex '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c') -Signature (ConvertFrom-TestHex '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00') -Message ([byte[]](0x72)) | Should -BeTrue
			}

			It "verifies a signature made by OpenSSL and rejects a changed message or signature" {
				$pub = ConvertFrom-TestHex '8f6381ab99f52b19be6673d6c81cc6741e8c80fcf288911693b31a65d3b6d1cb'
				$sig = ConvertFrom-TestHex 'c32ec41f2daf8cdbbbb84ab04039dc07a49a8f30afdc7faf3a75c8cd194e09f9d8c8813b8bc6db740976397322c81af0aecf309c65bb507dbcb9b07da5883d0c'
				$msg = [byte[]](1..37)
				Test-DnssecEd25519Signature -PublicKey $pub -Signature $sig -Message $msg | Should -BeTrue
				$bad = [byte[]](1..37); $bad[0] = 9
				Test-DnssecEd25519Signature -PublicKey $pub -Signature $sig -Message $bad | Should -BeFalse
				$sig2 = [byte[]]$sig.Clone(); $sig2[5] = $sig2[5] -bxor 4
				Test-DnssecEd25519Signature -PublicKey $pub -Signature $sig2 -Message $msg | Should -BeFalse
			}

			It "rejects wrong lengths without throwing" {
				Test-DnssecEd25519Signature -PublicKey ([byte[]](1..31)) -Signature ([byte[]](1..64)) -Message ([byte[]]@()) | Should -BeFalse
				Test-DnssecEd25519Signature -PublicKey ([byte[]](1..32)) -Signature ([byte[]](1..63)) -Message ([byte[]]@()) | Should -BeFalse
			}

			It "is used for DNSSEC algorithm 15" {
				$dnskey = [DnsDnskeyRecord]::new(256, 3, 15, (ConvertFrom-TestHex '8f6381ab99f52b19be6673d6c81cc6741e8c80fcf288911693b31a65d3b6d1cb'))
				$now = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
				$rrsig = [DnsRrsigRecord]::new(1, 15, 2, 300, ($now + 3600), ($now - 3600), 1, 'example.com', (ConvertFrom-TestHex 'c32ec41f2daf8cdbbbb84ab04039dc07a49a8f30afdc7faf3a75c8cd194e09f9d8c8813b8bc6db740976397322c81af0aecf309c65bb507dbcb9b07da5883d0c'))
				Test-DnssecSignature -SignedData ([byte[]](1..37)) -Rrsig $rrsig -Dnskey $dnskey | Should -BeTrue
			}
		}

		Context "Compare-DnsCanonicalName" {

			It "orders names by labels from the right (RFC 4034 section 6.1)" {
				$ordered = @('example', 'a.example', 'z.a.example', 'z.example', 'b.z.example')
				for ($i = 0; $i -lt $ordered.Count - 1; $i++) {
					Compare-DnsCanonicalName -A $ordered[$i] -B $ordered[$i + 1] | Should -BeLessThan 0
				}
			}

			It "ignores case and a trailing dot" {
				Compare-DnsCanonicalName -A 'WWW.Example.COM.' -B 'www.example.com' | Should -Be 0
			}

			It "puts the root first" {
				Compare-DnsCanonicalName -A '.' -B 'com' | Should -BeLessThan 0
			}
		}

		Context "Authenticated denial with NSEC" {

			BeforeEach {
				$script:zk = Get-TestZoneKey
				Mock Get-DnssecTrustedKey { [pscustomobject]@{ Status = 'Secure'; Reason = ''; Dnskeys = @($script:zk.Rr); DsRecords = @() } }
			}

			It "authenticates a NODATA answer from a signed NSEC" {
				$soa = Get-SoaRr
				$nsec = Get-NsecRr 'www.example.com' 'example.com' @(1, 46, 47)
				$resp = Get-NegativeResponse 0 @($soa, (Get-SignedRr $script:zk $soa), $nsec, (Get-SignedRr $script:zk $nsec))
				(Test-DnssecNegativeResponse -Response $resp -QueryName 'www.example.com' -QueryType 28).Status | Should -Be 'Secure'
			}

			It "rejects a NODATA denial when the NSEC lists the queried type" {
				$soa = Get-SoaRr
				$nsec = Get-NsecRr 'www.example.com' 'example.com' @(1, 28, 46, 47)
				$resp = Get-NegativeResponse 0 @($soa, (Get-SignedRr $script:zk $soa), $nsec, (Get-SignedRr $script:zk $nsec))
				(Test-DnssecNegativeResponse -Response $resp -QueryName 'www.example.com' -QueryType 28).Status | Should -Be 'Bogus'
			}

			It "authenticates an NXDOMAIN answer (name covered, wildcard covered)" {
				$soa = Get-SoaRr
				$nsec = Get-NsecRr 'example.com' 'www.example.com' @(2, 6, 46, 47, 48)
				$resp = Get-NegativeResponse 3 @($soa, (Get-SignedRr $script:zk $soa), $nsec, (Get-SignedRr $script:zk $nsec))
				$r = Test-DnssecNegativeResponse -Response $resp -QueryName 'm.example.com' -QueryType 1
				$r.Status | Should -Be 'Secure'
				$r.Kind | Should -Be 'NXDOMAIN'
			}

			It "rejects an NXDOMAIN answer whose NSEC does not cover the name" {
				$soa = Get-SoaRr
				$nsec = Get-NsecRr 'example.com' 'k.example.com' @(2, 6, 46, 47, 48)
				$resp = Get-NegativeResponse 3 @($soa, (Get-SignedRr $script:zk $soa), $nsec, (Get-SignedRr $script:zk $nsec))
				(Test-DnssecNegativeResponse -Response $resp -QueryName 'm.example.com' -QueryType 1).Status | Should -Be 'Bogus'
			}

			It "rejects an NXDOMAIN answer when a wildcard exists at the closest encloser" {
				$soa = Get-SoaRr
				$cover = Get-NsecRr 'example.com' '*.example.com' @(2, 6, 46, 47, 48)
				$wild = Get-NsecRr '*.example.com' 'www.example.com' @(1, 46, 47)
				$resp = Get-NegativeResponse 3 @($soa, (Get-SignedRr $script:zk $soa), $cover, (Get-SignedRr $script:zk $cover), $wild, (Get-SignedRr $script:zk $wild))
				(Test-DnssecNegativeResponse -Response $resp -QueryName 'a.example.com' -QueryType 1).Status | Should -Be 'Bogus'
			}

			It "rejects a denial with no NSEC/NSEC3 at all (stripped proof)" {
				$soa = Get-SoaRr
				$resp = Get-NegativeResponse 3 @($soa, (Get-SignedRr $script:zk $soa))
				(Test-DnssecNegativeResponse -Response $resp -QueryName 'm.example.com' -QueryType 1).Status | Should -Be 'Bogus'
			}

			It "rejects an unsigned NSEC" {
				$soa = Get-SoaRr
				$nsec = Get-NsecRr 'example.com' 'www.example.com' @(2, 6, 46, 47, 48)
				$resp = Get-NegativeResponse 3 @($soa, (Get-SignedRr $script:zk $soa), $nsec)
				(Test-DnssecNegativeResponse -Response $resp -QueryName 'm.example.com' -QueryType 1).Status | Should -Be 'Bogus'
			}
		}

		Context "Authenticated denial with NSEC3" {

			BeforeEach {
				$script:zk = Get-TestZoneKey
				Mock Get-DnssecTrustedKey { [pscustomobject]@{ Status = 'Secure'; Reason = ''; Dnskeys = @($script:zk.Rr); DsRecords = @() } }
			}

			It "authenticates an NXDOMAIN answer by closest-encloser proof" {
				$salt = [byte[]]@()
				$hCe = Get-DnssecNsec3Hash -name 'example.com.' -Algorithm 1 -Iterations 0 -salt $salt
				$hNc = Get-DnssecNsec3Hash -name 'nope.example.com.' -Algorithm 1 -Iterations 0 -salt $salt
				$hW = Get-DnssecNsec3Hash -name '*.example.com.' -Algorithm 1 -Iterations 0 -salt $salt
				$mkRr = {
					param($Owner, $Next, $Types)
					$n3 = [DnsNsec3Record]::new(1, 0, 0, $salt, $Owner, $Next, [int[]]$Types)
					[DnsResourceRecord]::new('x' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.example.com', 50, 1, 300, $n3.ToWire(), $n3)
				}
				$ce = & $mkRr $hCe (Get-AdjustedHash $hCe 1) @(2, 6, 46)
				$nc = & $mkRr (Get-AdjustedHash $hNc -1) (Get-AdjustedHash $hNc 1) @(1)
				$wc = & $mkRr (Get-AdjustedHash $hW -1) (Get-AdjustedHash $hW 1) @(1)
				$soa = Get-SoaRr
				$resp = Get-NegativeResponse 3 @($soa, (Get-SignedRr $script:zk $soa), $ce, (Get-SignedRr $script:zk $ce), $nc, (Get-SignedRr $script:zk $nc), $wc, (Get-SignedRr $script:zk $wc))
				$r = Test-DnssecNegativeResponse -Response $resp -QueryName 'nope.example.com' -QueryType 1
				$r.Status | Should -Be 'Secure'
			}

			It "rejects the NSEC3 NXDOMAIN proof when the wildcard is not covered" {
				$salt = [byte[]]@()
				$hCe = Get-DnssecNsec3Hash -name 'example.com.' -Algorithm 1 -Iterations 0 -salt $salt
				$hNc = Get-DnssecNsec3Hash -name 'nope.example.com.' -Algorithm 1 -Iterations 0 -salt $salt
				$mkRr = {
					param($Owner, $Next, $Types)
					$n3 = [DnsNsec3Record]::new(1, 0, 0, $salt, $Owner, $Next, [int[]]$Types)
					[DnsResourceRecord]::new('x' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.example.com', 50, 1, 300, $n3.ToWire(), $n3)
				}
				$ce = & $mkRr $hCe (Get-AdjustedHash $hCe 1) @(2, 6, 46)
				$nc = & $mkRr (Get-AdjustedHash $hNc -1) (Get-AdjustedHash $hNc 1) @(1)
				$soa = Get-SoaRr
				$resp = Get-NegativeResponse 3 @($soa, (Get-SignedRr $script:zk $soa), $ce, (Get-SignedRr $script:zk $ce), $nc, (Get-SignedRr $script:zk $nc))
				(Test-DnssecNegativeResponse -Response $resp -QueryName 'nope.example.com' -QueryType 1).Status | Should -Be 'Bogus'
			}

			It "authenticates a NODATA answer from the matching NSEC3" {
				$salt = [byte[]]@()
				$h = Get-DnssecNsec3Hash -name 'www.example.com.' -Algorithm 1 -Iterations 0 -salt $salt
				$n3 = [DnsNsec3Record]::new(1, 0, 0, $salt, $h, (Get-AdjustedHash $h 5), [int[]](1, 46))
				$rr = [DnsResourceRecord]::new('abcdefgh.example.com', 50, 1, 300, $n3.ToWire(), $n3)
				$soa = Get-SoaRr
				$resp = Get-NegativeResponse 0 @($soa, (Get-SignedRr $script:zk $soa), $rr, (Get-SignedRr $script:zk $rr))
				(Test-DnssecNegativeResponse -Response $resp -QueryName 'www.example.com' -QueryType 28).Status | Should -Be 'Secure'
			}
		}

		Context "Unauthenticated zone" {

			It "reports Insecure (not Bogus) when the zone is provably unsigned" {
				Mock Get-DnssecTrustedKey { [pscustomobject]@{ Status = 'Insecure'; Reason = 'unsigned'; Dnskeys = @(); DsRecords = @() } }
				$resp = Get-NegativeResponse 3 @((Get-SoaRr))
				(Test-DnssecNegativeResponse -Response $resp -QueryName 'm.example.com' -QueryType 1).Status | Should -Be 'Insecure'
			}
		}
	}
}
