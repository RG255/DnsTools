# Tests/29-ReviewFixes.Tests.ps1
# Regression tests for the second 0.8 code review: negative-answer replay, wildcard proofs, per-RRset signature
# outcomes, unsupported algorithms, reply matching, trust-anchor update safety, DoH/DoT address parsing.

using module dnstools

InModuleScope DnsTools {

	Describe "0.8 review fixes" {

		BeforeAll {
			function Get-ZoneKey {
				$curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
				$ecdsa = [System.Security.Cryptography.ECDsa]::Create($curve)
				$p = $ecdsa.ExportParameters($false)
				$pub = [byte[]]($p.Q.X + $p.Q.Y)
				$dnskey = [DnsDnskeyRecord]::new(256, 3, 13, $pub)
				[pscustomobject]@{ Ecdsa = $ecdsa; Dnskey = $dnskey; Rr = [DnsResourceRecord]::new('example.com', 48, 1, 3600, $pub, $dnskey) }
			}

			function Get-SignedRr {
				param($Key, $Rr, [string]$Signer = 'example.com', [int]$Labels = -1)
				$now = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
				if ($Labels -lt 0) { $Labels = @($Rr.Name.TrimEnd('.').Split('.') | Where-Object { $_ -ne '' }).Count }
				$stub = [DnsRrsigRecord]::new([uint16]$Rr.Type, 13, [byte]$Labels, 300, ($now + 3600), ($now - 3600), $Key.Dnskey.KeyTag, $Signer, [byte[]]@())
				$data = Get-DnssecSignedData -Rrsig $stub -Rrset @($Rr)
				$sig = $Key.Ecdsa.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
				$rrsig = [DnsRrsigRecord]::new([uint16]$Rr.Type, 13, [byte]$Labels, 300, ($now + 3600), ($now - 3600), $Key.Dnskey.KeyTag, $Signer, $sig)
				[DnsResourceRecord]::new($Rr.Name, 46, 1, 300, [byte[]]@(), $rrsig)
			}

			function Get-SoaRr {
				param([string]$Owner = 'example.com')
				$soa = [DnsSoaRecord]::new('ns.example.com', 'h.example.com', 1, 2, 3, 4, 5)
				[DnsResourceRecord]::new($Owner, 6, 1, 300, $soa.ToWire(), $soa)
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

			function Get-ARr {
				param([string]$Owner)
				[DnsResourceRecord]::new($Owner, 1, 1, 300, [byte[]](192, 0, 2, 1), [DnsARecord]@{ Address = '192.0.2.1' })
			}

			function Get-Nsec3Rr {
				param($Owner, $Next, $Types, [byte]$Flags = 0, [uint16]$Iterations = 0)
				$n3 = [DnsNsec3Record]::new(1, $Flags, $Iterations, [byte[]]@(), $Owner, $Next, [int[]]$Types)
				[DnsResourceRecord]::new('x' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.example.com', 50, 1, 300, $n3.ToWire(), $n3)
			}
			function Get-AdjustedHash {
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

		Context "Negative answers cannot be replayed from another zone" {

			BeforeEach {
				$script:zk = Get-ZoneKey
				Mock Get-DnssecTrustedKey { [pscustomobject]@{ Status = 'Secure'; Reason = ''; Dnskeys = @($script:zk.Rr); DsRecords = @() } }
			}

			It "rejects an SOA from a zone that does not contain the query name" {
				$soa = Get-SoaRr -Owner 'other.test'
				$nsec = Get-NsecRr 'other.test' 'zzz.other.test' @(2, 6, 46, 47)
				$resp = Get-NegativeResponse 3 @($soa, (Get-SignedRr $script:zk $soa 'other.test'), $nsec, (Get-SignedRr $script:zk $nsec 'other.test'))
				(Test-DnssecNegativeResponse -Response $resp -QueryName 'www.example.com' -QueryType 1).Status | Should -Be 'Bogus'
			}

			It "rejects a root delegation NSEC (com. -> comcast.) replayed as an NXDOMAIN proof for www.example.com" {
				$soa = Get-SoaRr -Owner ''
				$nsec = Get-NsecRr 'com' 'comcast' @(2, 43, 46, 47)
				$resp = Get-NegativeResponse 3 @($soa, (Get-SignedRr $script:zk $soa ''), $nsec, (Get-SignedRr $script:zk $nsec ''))
				(Test-DnssecNegativeResponse -Response $resp -QueryName 'www.example.com' -QueryType 1).Status | Should -Be 'Bogus'
			}

			It "rejects a delegation NSEC (NS, no SOA) as a NODATA proof for a non-DS type" {
				$soa = Get-SoaRr
				$nsec = Get-NsecRr 'sub.example.com' 'zzz.example.com' @(2, 43, 46, 47)
				$resp = Get-NegativeResponse 0 @($soa, (Get-SignedRr $script:zk $soa), $nsec, (Get-SignedRr $script:zk $nsec))
				(Test-DnssecNegativeResponse -Response $resp -QueryName 'sub.example.com' -QueryType 1).Status | Should -Be 'Bogus'
			}

			It "still accepts that delegation NSEC as the proof that no DS exists" {
				$soa = Get-SoaRr
				$nsec = Get-NsecRr 'sub.example.com' 'zzz.example.com' @(2, 46, 47)
				$resp = Get-NegativeResponse 0 @($soa, (Get-SignedRr $script:zk $soa), $nsec, (Get-SignedRr $script:zk $nsec))
				(Test-DnssecNegativeResponse -Response $resp -QueryName 'sub.example.com' -QueryType 43).Status | Should -Be 'Secure'
			}
		}

		Context "NSEC3 parameters and opt-out" {

			BeforeEach {
				$script:zk = Get-ZoneKey
				Mock Get-DnssecTrustedKey { [pscustomobject]@{ Status = 'Secure'; Reason = ''; Dnskeys = @($script:zk.Rr); DsRecords = @() } }
				$script:salt = [byte[]]@()
				$script:hCe = Get-DnssecNsec3Hash -name 'example.com.' -Algorithm 1 -Iterations 0 -salt $script:salt
				$script:hNc = Get-DnssecNsec3Hash -name 'nope.example.com.' -Algorithm 1 -Iterations 0 -salt $script:salt
				$script:hW = Get-DnssecNsec3Hash -name '*.example.com.' -Algorithm 1 -Iterations 0 -salt $script:salt
			}

			It "reports an opt-out span as Insecure, not Secure" {
				$ce = Get-Nsec3Rr $script:hCe (Get-AdjustedHash $script:hCe 1) @(2, 6, 46)
				$nc = Get-Nsec3Rr (Get-AdjustedHash $script:hNc -1) (Get-AdjustedHash $script:hNc 1) @(1) 1
				$wc = Get-Nsec3Rr (Get-AdjustedHash $script:hW -1) (Get-AdjustedHash $script:hW 1) @(1)
				$soa = Get-SoaRr
				$resp = Get-NegativeResponse 3 @($soa, (Get-SignedRr $script:zk $soa), $ce, (Get-SignedRr $script:zk $ce), $nc, (Get-SignedRr $script:zk $nc), $wc, (Get-SignedRr $script:zk $wc))
				(Test-DnssecNegativeResponse -Response $resp -QueryName 'nope.example.com' -QueryType 1).Status | Should -Be 'Insecure'
			}

			It "does not accept NSEC3 records with different hash parameters" {
				$ce = Get-Nsec3Rr $script:hCe (Get-AdjustedHash $script:hCe 1) @(2, 6, 46)
				$nc = Get-Nsec3Rr (Get-AdjustedHash $script:hNc -1) (Get-AdjustedHash $script:hNc 1) @(1) 0 5
				$soa = Get-SoaRr
				$resp = Get-NegativeResponse 3 @($soa, (Get-SignedRr $script:zk $soa), $ce, (Get-SignedRr $script:zk $ce), $nc, (Get-SignedRr $script:zk $nc))
				(Test-DnssecNegativeResponse -Response $resp -QueryName 'nope.example.com' -QueryType 1).Status | Should -Be 'Indeterminate'
			}

			It "rejects a closest encloser that is a delegation point" {
				$salt = [byte[]]@()
				$hCe = Get-DnssecNsec3Hash -name 'sub.example.com.' -Algorithm 1 -Iterations 0 -salt $salt
				$hNc = Get-DnssecNsec3Hash -name 'nope.sub.example.com.' -Algorithm 1 -Iterations 0 -salt $salt
				$hW = Get-DnssecNsec3Hash -name '*.sub.example.com.' -Algorithm 1 -Iterations 0 -salt $salt
				$ce = Get-Nsec3Rr $hCe (Get-AdjustedHash $hCe 1) @(2, 46)
				$nc = Get-Nsec3Rr (Get-AdjustedHash $hNc -1) (Get-AdjustedHash $hNc 1) @(1)
				$wc = Get-Nsec3Rr (Get-AdjustedHash $hW -1) (Get-AdjustedHash $hW 1) @(1)
				$soa = Get-SoaRr
				$resp = Get-NegativeResponse 3 @($soa, (Get-SignedRr $script:zk $soa), $ce, (Get-SignedRr $script:zk $ce), $nc, (Get-SignedRr $script:zk $nc), $wc, (Get-SignedRr $script:zk $wc))
				(Test-DnssecNegativeResponse -Response $resp -QueryName 'nope.sub.example.com' -QueryType 1).Status | Should -Be 'Bogus'
			}		}

		Context "Response signatures: per-RRset outcome, wildcards, unsupported algorithms" {

			BeforeEach {
				$script:zk = Get-ZoneKey
				Mock Get-DnssecTrustedKey { [pscustomobject]@{ Status = 'Secure'; Reason = ''; Dnskeys = @($script:zk.Rr); DsRecords = @() } }
			}

			It "is Secure when a later RRSIG verifies even though an earlier one names an unknown key (rollover)" {
				$a = Get-ARr 'www.example.com'
				$good = Get-SignedRr $script:zk $a
				$now = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
				$stale = [DnsResourceRecord]::new('www.example.com', 46, 1, 300, [byte[]]@(), [DnsRrsigRecord]::new(1, 13, 3, 300, ($now + 3600), ($now - 3600), 12345, 'example.com', [byte[]](1..64)))
				(Test-DnssecResponseSignature -Answers @($a, $stale, $good)).Status | Should -Be 'Secure'
			}

			It "is Secure when the first RRSIG uses an unsupported algorithm but a later one verifies" {
				$a = Get-ARr 'www.example.com'
				$good = Get-SignedRr $script:zk $a
				$now = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
				$ed448 = [DnsResourceRecord]::new('www.example.com', 46, 1, 300, [byte[]]@(), [DnsRrsigRecord]::new(1, 16, 3, 300, ($now + 3600), ($now - 3600), 999, 'example.com', [byte[]](1..114)))
				(Test-DnssecResponseSignature -Answers @($a, $ed448, $good)).Status | Should -Be 'Secure'
			}

			It "is Insecure, not Bogus, when the only signature uses an algorithm this module cannot verify" {
				$a = Get-ARr 'www.example.com'
				$now = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
				$ed448 = [DnsResourceRecord]::new('www.example.com', 46, 1, 300, [byte[]]@(), [DnsRrsigRecord]::new(1, 16, 3, 300, ($now + 3600), ($now - 3600), 999, 'example.com', [byte[]](1..114)))
				(Test-DnssecResponseSignature -Answers @($a, $ed448)).Status | Should -Be 'Insecure'
			}

			It "is Bogus when the only signature is wrong for a supported algorithm" {
				$a = Get-ARr 'www.example.com'
				$good = Get-SignedRr $script:zk $a
				$tampered = Get-ARr 'www.example.com'
				$tampered.RawRData[3] = 99
				(Test-DnssecResponseSignature -Answers @($tampered, $good)).Status | Should -Be 'Bogus'
			}

			It "needs the signed non-existence proof for a wildcard-expanded answer" {
				$a = Get-ARr 'www.example.com'
				$wildSig = Get-SignedRr $script:zk $a 'example.com' 2
				# no authority supplied -> cannot be proven
				(Test-DnssecResponseSignature -Answers @($a, $wildSig)).Status | Should -Be 'Indeterminate'
				# authority supplied but no covering NSEC -> not a valid synthesis
				$soa = Get-SoaRr
				(Test-DnssecResponseSignature -Answers @($a, $wildSig) -Authority @($soa, (Get-SignedRr $script:zk $soa))).Status | Should -Be 'Bogus'
			}

			It "accepts a wildcard-expanded answer with a signed NSEC covering the exact name" {
				$a = Get-ARr 'www.example.com'
				$wildSig = Get-SignedRr $script:zk $a 'example.com' 2
				$nsec = Get-NsecRr 'example.com' 'zzz.example.com' @(2, 6, 46, 47)
				$auth = @($nsec, (Get-SignedRr $script:zk $nsec))
				(Test-DnssecResponseSignature -Answers @($a, $wildSig) -Authority $auth).Status | Should -Be 'Secure'
			}

			It "rejects a wildcard-expanded answer whose NSEC does not cover the exact name" {
				$a = Get-ARr 'zzzz.example.com'
				$wildSig = Get-SignedRr $script:zk $a 'example.com' 2
				$nsec = Get-NsecRr 'example.com' 'www.example.com' @(2, 6, 46, 47)
				$auth = @($nsec, (Get-SignedRr $script:zk $nsec))
				(Test-DnssecResponseSignature -Answers @($a, $wildSig) -Authority $auth).Status | Should -Be 'Bogus'
			}
		}

		Context "Algorithm support table" {

			It "knows which signature algorithms and DS digest types it can handle" {
				foreach ($alg in 5, 7, 8, 10, 13, 14, 15) { Test-DnssecAlgorithmSupported -Algorithm $alg | Should -BeTrue }
				foreach ($alg in 1, 3, 12, 16) { Test-DnssecAlgorithmSupported -Algorithm $alg | Should -BeFalse }
				foreach ($d in 1, 2, 4) { Test-DnssecAlgorithmSupported -DigestType $d | Should -BeTrue }
				foreach ($d in 0, 3, 99) { Test-DnssecAlgorithmSupported -DigestType $d | Should -BeFalse }
			}
		}

		Context "Test-DnsReplyMatch" {

			BeforeAll {
				$script:q = [byte[]](New-DnsQueryPacket -name 'Example.COM' -type 1)
			}

			It "accepts a reply with the same ID, QR set and the same question (case-insensitive)" {
				$r = [byte[]]$script:q.Clone(); $r[2] = $r[2] -bor 0x80
				Test-DnsReplyMatch -Query $script:q -Reply $r | Should -BeTrue
				$lower = [byte[]]$r.Clone()
				for ($i = 12; $i -lt $lower.Length; $i++) { if ($lower[$i] -ge 65 -and $lower[$i] -le 90) { $lower[$i] += 32 } }
				Test-DnsReplyMatch -Query $script:q -Reply $lower | Should -BeTrue
			}

			It "rejects a different ID, a missing QR bit, a different question and a short reply" {
				$r = [byte[]]$script:q.Clone(); $r[2] = $r[2] -bor 0x80
				$badId = [byte[]]$r.Clone(); $badId[1] = $badId[1] -bxor 1
				Test-DnsReplyMatch -Query $script:q -Reply $badId | Should -BeFalse
				Test-DnsReplyMatch -Query $script:q -Reply $script:q | Should -BeFalse
				$badQ = [byte[]]$r.Clone(); $badQ[13] = [byte][char]'z'
				Test-DnsReplyMatch -Query $script:q -Reply $badQ | Should -BeFalse
				Test-DnsReplyMatch -Query $script:q -Reply ([byte[]]$r[0..10]) | Should -BeFalse
			}
		}

		Context "Update-DnssecTrustAnchorFile" {

			It "does not write the file under -Force -WhatIf" {
				$xml = '<?xml version="1.0"?><TrustAnchor id="x" source="y"><Zone>.</Zone><KeyDigest id="k" validFrom="2010-07-15T00:00:00+00:00"><KeyTag>1</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType><Digest>AABBCC</Digest></KeyDigest></TrustAnchor>'
				Mock Invoke-WebRequest { [pscustomobject]@{ RawContentStream = [System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($xml)) } }
				$out = Join-Path ([System.IO.Path]::GetTempPath()) ('ta-' + [Guid]::NewGuid().ToString('N') + '.json')
				try {
					$null = Update-DnssecTrustAnchorFile -OutputPath $out -Force -WhatIf -SkipSignatureCheck 6>$null
					Test-Path -LiteralPath $out | Should -BeFalse
				}
				finally {
					if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Force }
				}
			}

			It "refuses anchors whose IANA signature cannot be fetched or verified" {
				Mock Invoke-WebRequest {
					if ($Uri -like '*.p7s') { throw 'no signature available' }
					[pscustomobject]@{ RawContentStream = [System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes('<TrustAnchor><Zone>.</Zone></TrustAnchor>')) }
				}
				{ Update-DnssecTrustAnchorFile -OutputPath (Join-Path ([System.IO.Path]::GetTempPath()) 'never.json') -Force 6>$null } | Should -Throw '*NOT used*'
			}
		}

		Context "DoH / DoT address forms" {

			It "accepts an IPv6 literal DoH URL as valid input (fails later as a transport error, not InvalidArgument)" {
				(Resolve-DnsIterative -Name example.com -Type A -DoH 'https://[::1]:1/dns-query').Status | Should -Not -Be 'InvalidArgument'
			}

			It "accepts a bracketed IPv6 DoT address without a port" {
				(Resolve-DnsIterative -Name example.com -Type A -DoT '[::1]').Status | Should -Not -Be 'InvalidArgument'
			}
		}
	}
}
