# Tests/25-DnssecValidationFixes.Tests.ps1
# Regression tests for the 0.8 DNSSEC fixes: RRSIG results are objects (always truthy), canonical RDATA,
# zero-length reads, root name encoding, multiple trust anchors, signer/key selection.

using module dnstools

InModuleScope DnsTools {

	Describe "DNSSEC 0.8 fixes" {

		BeforeAll {
			function Get-TestKey {
				$curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
				$ecdsa = [System.Security.Cryptography.ECDsa]::Create($curve)
				$p = $ecdsa.ExportParameters($false)
				$pub = [byte[]]($p.Q.X + $p.Q.Y)
				$dnskey = [DnsDnskeyRecord]::new(256, 3, 13, $pub)
				$rr = [DnsResourceRecord]::new('example.com', 48, 1, 3600, $pub, $dnskey)
				[pscustomobject]@{ Ecdsa = $ecdsa; Dnskey = $dnskey; Rr = $rr }
			}

			function Get-SignedARrset {
				param($Key, [string]$Owner = 'example.com', [string]$Signer = 'example.com', [byte]$Labels = 2)
				$a = [DnsARecord]@{ Address = '192.0.2.1' }
				$rr = [DnsResourceRecord]::new($Owner, 1, 1, 300, [byte[]](192, 0, 2, 1), $a)
				$now = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
				$stub = [DnsRrsigRecord]::new(1, 13, $Labels, 300, ($now + 3600), ($now - 3600), $Key.Dnskey.KeyTag, $Signer, [byte[]]@())
				$data = Get-DnssecSignedData -Rrsig $stub -Rrset @($rr)
				$sig = $Key.Ecdsa.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
				$rrsig = [DnsRrsigRecord]::new(1, 13, $Labels, 300, ($now + 3600), ($now - 3600), $Key.Dnskey.KeyTag, $Signer, $sig)
				$sigRr = [DnsResourceRecord]::new($Owner, 46, 1, 300, [byte[]]@(), $rrsig)
				[pscustomobject]@{ Rr = $rr; SigRr = $sigRr }
			}
		}

		Context "Test-DnssecRrsetSignature" {

			It "accepts a correctly signed RRset" {
				$k = Get-TestKey
				$s = Get-SignedARrset -Key $k
				(Test-DnssecRrsetSignature -Rrset @($s.Rr) -Rrsigs @($s.SigRr) -KeyRecords @($k.Rr) -ZoneName 'example.com').Valid | Should -BeTrue
			}

			It "rejects a signature made by a different key (the .Valid property is honoured)" {
				$k = Get-TestKey
				$other = Get-TestKey
				$s = Get-SignedARrset -Key $other
				$s.SigRr.RDataObject.KeyTag = $k.Dnskey.KeyTag
				(Test-DnssecRrsetSignature -Rrset @($s.Rr) -Rrsigs @($s.SigRr) -KeyRecords @($k.Rr) -ZoneName 'example.com').Valid | Should -BeFalse
			}

			It "rejects tampered RDATA" {
				$k = Get-TestKey
				$s = Get-SignedARrset -Key $k
				$tampered = [DnsResourceRecord]::new('example.com', 1, 1, 300, [byte[]](192, 0, 2, 99), [DnsARecord]@{ Address = '192.0.2.99' })
				(Test-DnssecRrsetSignature -Rrset @($tampered) -Rrsigs @($s.SigRr) -KeyRecords @($k.Rr) -ZoneName 'example.com').Valid | Should -BeFalse
			}

			It "rejects a signer that is not the expected zone" {
				$k = Get-TestKey
				$s = Get-SignedARrset -Key $k -Signer 'evil.test'
				(Test-DnssecRrsetSignature -Rrset @($s.Rr) -Rrsigs @($s.SigRr) -KeyRecords @($k.Rr) -ZoneName 'example.com').Valid | Should -BeFalse
			}

			It "verifies a wildcard-expanded answer (owner longer than RRSIG Labels)" {
				$k = Get-TestKey
				$s = Get-SignedARrset -Key $k -Owner 'www.example.com' -Labels 2
				(Test-DnssecRrsetSignature -Rrset @($s.Rr) -Rrsigs @($s.SigRr) -KeyRecords @($k.Rr) -ZoneName 'example.com').Valid | Should -BeTrue
			}

			It "does not trust a key without the zone-key flag" {
				$k = Get-TestKey
				$s = Get-SignedARrset -Key $k
				$noZone = [DnsDnskeyRecord]::new(0, 3, 13, $k.Dnskey.PublicKey)
				$noZoneRr = [DnsResourceRecord]::new('example.com', 48, 1, 3600, $noZone.PublicKey, $noZone)
				(Test-DnssecRrsetSignature -Rrset @($s.Rr) -Rrsigs @($s.SigRr) -KeyRecords @($noZoneRr) -ZoneName 'example.com').Valid | Should -BeFalse
			}
		}

		Context "Get-DnssecDsMatchedKey" {

			It "returns only the key the DS authenticates, not an attacker key added beside it" {
				$real = Get-TestKey
				$attacker = Get-TestKey
				$digest = Get-DnssecKeyDigest -OwnerName 'example.com' -Dnskey $real.Dnskey -DigestType 2
				$ds = [DnsDsRecord]::new($real.Dnskey.KeyTag, 13, 2, $digest)
				$dsRr = [DnsResourceRecord]::new('example.com', 43, 1, 3600, $digest, $ds)
				$matched = @(Get-DnssecDsMatchedKey -DsRecords @($dsRr) -DnskeyRecords @($real.Rr, $attacker.Rr) -Zone 'example.com')
				$matched.Count | Should -Be 1
				$matched[0].RDataObject.KeyTag | Should -Be $real.Dnskey.KeyTag
			}

			It "skips an unsupported digest type instead of throwing" {
				$real = Get-TestKey
				$ds = [DnsDsRecord]::new($real.Dnskey.KeyTag, 13, 99, [byte[]](1, 2, 3))
				$dsRr = [DnsResourceRecord]::new('example.com', 43, 1, 3600, [byte[]](1, 2, 3), $ds)
				{ Get-DnssecDsMatchedKey -DsRecords @($dsRr) -DnskeyRecords @($real.Rr) -Zone 'example.com' } | Should -Not -Throw
				@(Get-DnssecDsMatchedKey -DsRecords @($dsRr) -DnskeyRecords @($real.Rr) -Zone 'example.com').Count | Should -Be 0
			}
		}

		Context "Canonical RDATA and wire primitives" {

			It "rebuilds NS RDATA uncompressed (the received bytes held a compression pointer)" {
				# offset 0: example.com ; offset 13: 'ns1' + pointer to offset 0
				$name = [byte[]](7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0)
				$rdata = [byte[]](3, 78, 83, 49, 0xC0, 0x00)
				$r = [DnsBinaryReader]::new([byte[]]($name + $rdata))
				$r.Position = 13
				$ns = [DnsNsRecord]::Parse($r, 6)
				$rr = [DnsResourceRecord]::new('example.com', 2, 1, 300, $rdata, $ns)
				$expected = [byte[]](3, 110, 115, 49, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0)
				($rr.GetCanonicalRData() -join ',') | Should -Be ($expected -join ',')
				($rr.RawRData -join ',') | Should -Not -Be ($expected -join ',')
			}

			It "leaves A RDATA as received" {
				$rr = [DnsResourceRecord]::new('example.com', 1, 1, 300, [byte[]](192, 0, 2, 1), [DnsARecord]@{ Address = '192.0.2.1' })
				($rr.GetCanonicalRData() -join ',') | Should -Be '192,0,2,1'
			}

			It "ReadBytes(0) returns an empty array and does not advance" {
				$r = [DnsBinaryReader]::new([byte[]](1, 2, 3))
				$r.Position = 1
				$b = $r.ReadBytes(0)
				$b.Length | Should -Be 0
				$r.Position | Should -Be 1
			}

			It "encodes the root name as a single zero byte" {
				(Get-DnssecCanonicalNameWire -name '.') -join ',' | Should -Be '0'
				(Get-DnssecCanonicalNameWire -name '') -join ',' | Should -Be '0'
			}
		}

		Context "Trust anchor store" {

			BeforeEach {
				$script:savedAnchors = if (Get-Variable -Name TrustAnchors -Scope Script -ErrorAction SilentlyContinue) { $script:TrustAnchors } else { $null }
				$script:TrustAnchors = @{}
			}
			AfterEach {
				$script:TrustAnchors = $script:savedAnchors
			}

			It "keeps more than one anchor per zone" {
				Add-DnssecTrustAnchor -Zone '.' -keyTag 20326 -Algorithm 8 -DigestType 2 -DigestHex 'AA'
				Add-DnssecTrustAnchor -Zone '.' -keyTag 38696 -Algorithm 8 -DigestType 2 -DigestHex 'BB'
				@(Get-DnssecTrustAnchorStore | Where-Object { $_.Zone -eq '.' }).Count | Should -Be 2
			}

			It "does not add an identical anchor twice" {
				Add-DnssecTrustAnchor -Zone '.' -keyTag 1 -Algorithm 8 -DigestType 2 -DigestHex 'AA'
				Add-DnssecTrustAnchor -Zone '.' -keyTag 1 -Algorithm 8 -DigestType 2 -DigestHex 'aa'
				@(Get-DnssecTrustAnchorStore).Count | Should -Be 1
			}

			It "anchors a key that matches the SECOND anchor for the zone" {
				$k = Get-TestKey
				$hex = Get-DnssecKeyDigestHex -OwnerName '.' -Dnskey $k.Dnskey -DigestType 2
				Add-DnssecTrustAnchor -Zone '.' -keyTag 1 -Algorithm 8 -DigestType 2 -DigestHex 'AA'
				Add-DnssecTrustAnchor -Zone '.' -keyTag $k.Dnskey.KeyTag -Algorithm 13 -DigestType 2 -DigestHex $hex
				Test-DnssecAnchoredDnskey -Zone '.' -Dnskey $k.Dnskey | Should -BeTrue
			}

			It "does not anchor a key that matches no anchor" {
				$k = Get-TestKey
				Add-DnssecTrustAnchor -Zone '.' -keyTag 1 -Algorithm 8 -DigestType 2 -DigestHex 'AA'
				Test-DnssecAnchoredDnskey -Zone '.' -Dnskey $k.Dnskey | Should -BeFalse
			}
		}

		Context "Test-DnssecChain" {

			It "rejects a DNSKEY RRset whose RRSIG does not verify (object truthiness regression)" {
				$k = Get-TestKey
				$digest = Get-DnssecKeyDigest -OwnerName 'example.com' -Dnskey $k.Dnskey -DigestType 2
				$ds = [DnsDsRecord]::new($k.Dnskey.KeyTag, 13, 2, $digest)
				$dsRr = [DnsResourceRecord]::new('example.com', 43, 1, 3600, $digest, $ds)
				$now = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
				$badSig = [DnsRrsigRecord]::new(48, 13, 2, 3600, ($now + 3600), ($now - 3600), $k.Dnskey.KeyTag, 'example.com', ([byte[]]::new(64)))
				$sigRr = [DnsResourceRecord]::new('example.com', 46, 1, 3600, [byte[]]@(), $badSig)
				$result = Test-DnssecChain -DnskeyRrset @($k.Rr) -DsRrset @($dsRr) -RrsigRrset @($sigRr) -ZoneName 'example.com'
				$result.Valid | Should -BeFalse
			}
		}
	}
}
