# Tests/30-TrustChainWalk.Tests.ps1
# Exercises Get-DnssecTrustedKey itself (root anchoring, parent-signed DS, DS-matched DNSKEY, unsupported DS, bad DS)
# against a small synthetic hierarchy, with the network functions mocked. The other DNSSEC tests mock Get-DnssecTrustedKey
# away, so this is the only place the walk's own code runs offline.

using module dnstools

InModuleScope DnsTools {

	Describe "Get-DnssecTrustedKey chain walk" {

		BeforeAll {
			function Get-ChainKey {
				param([uint16]$Flags = 257)
				$curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
				$ecdsa = [System.Security.Cryptography.ECDsa]::Create($curve)
				$p = $ecdsa.ExportParameters($false)
				$pub = [byte[]]($p.Q.X + $p.Q.Y)
				[pscustomobject]@{ Ecdsa = $ecdsa; Dnskey = [DnsDnskeyRecord]::new($Flags, 3, 13, $pub); Pub = $pub }
			}

			function Get-KeyRr {
				param($Key, [string]$Owner)
				[DnsResourceRecord]::new($Owner, 48, 1, 3600, $Key.Pub, $Key.Dnskey)
			}

			function Get-SigRr {
				param($Key, $Rr, [string]$Signer)
				$now = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
				$labels = @($Rr.Name.TrimEnd('.').Split('.') | Where-Object { $_ -ne '' }).Count
				$stub = [DnsRrsigRecord]::new([uint16]$Rr.Type, 13, [byte]$labels, 300, ($now + 3600), ($now - 3600), $Key.Dnskey.KeyTag, $Signer, [byte[]]@())
				$data = Get-DnssecSignedData -Rrsig $stub -Rrset @($Rr)
				$sig = $Key.Ecdsa.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
				[DnsResourceRecord]::new($Rr.Name, 46, 1, 300, [byte[]]@(), [DnsRrsigRecord]::new([uint16]$Rr.Type, 13, [byte]$labels, 300, ($now + 3600), ($now - 3600), $Key.Dnskey.KeyTag, $Signer, $sig))
			}

			function Get-DsRr {
				param($Key, [string]$Owner, [byte]$DigestType = 2, [byte]$Algorithm = 13, [switch]$WrongDigest)
				$digest = Get-DnssecKeyDigest -OwnerName $Owner -Dnskey $Key.Dnskey -DigestType 2
				if ($DigestType -ne 2) { $digest = [byte[]](1..32) }
				if ($WrongDigest) { $digest = [byte[]](1..32) }
				$ds = [DnsDsRecord]::new($Key.Dnskey.KeyTag, $Algorithm, $DigestType, $digest)
				[DnsResourceRecord]::new($Owner, 43, 1, 3600, $digest, $ds)
			}

			function Get-AnswerPacket {
				param([object[]]$Answers)
				$p = [DnsPacket]::new()
				$p.Header = [DnsHeader]::new(1, 0x8400, 1, [uint16]$Answers.Count, 0, 0)
				foreach ($a in $Answers) { $null = $p.Answers.Add($a) }
				$p
			}
		}

		BeforeEach {
			Mock Write-MyCatchAudit { }
			$script:rootKey = Get-ChainKey
			$script:kskKey = Get-ChainKey
			$rootRr = Get-KeyRr $script:rootKey ''
			$rootSig = Get-SigRr $script:rootKey $rootRr ''
			$script:rootPacket = Get-AnswerPacket @($rootRr, $rootSig)

			# Anchor the synthetic root key.
			$saved = if (Get-Variable -Name TrustAnchors -Scope Script -ErrorAction SilentlyContinue) { $script:TrustAnchors } else { $null }
			$script:savedAnchors = $saved
			$script:TrustAnchors = @{}
			$hex = Get-DnssecKeyDigestHex -OwnerName '.' -Dnskey $script:rootKey.Dnskey -DigestType 2
			Add-DnssecTrustAnchor -Zone '.' -keyTag $script:rootKey.Dnskey.KeyTag -Algorithm 13 -DigestType 2 -DigestHex $hex

			Mock Invoke-DnsUdpQuery { [byte[]]@(0) }
			Mock ConvertFrom-DnsPacket { $script:rootPacket }
			# In this synthetic hierarchy only the root is a parent: nothing between the root and the zone under test is a zone cut.
			Mock Test-DnsZoneApex { $false }
		}

		AfterEach {
			$script:TrustAnchors = $script:savedAnchors
		}

		It "anchors the root DNSKEY set to the trust anchor" {
			$r = Get-DnssecTrustedKey -Zone '.' -RootServers '192.0.2.1'
			$r.Status | Should -Be 'Secure'
		}

		It "reports Indeterminate when no root trust anchor is configured" {
			$script:TrustAnchors = @{}
			Mock Initialize-DnssecTrustAnchorFile { }
			(Get-DnssecTrustedKey -Zone '.' -RootServers '192.0.2.1').Status | Should -Be 'Indeterminate'
		}

		It "reports Bogus when the root DNSKEY matches no trust anchor" {
			$script:TrustAnchors = @{}
			Add-DnssecTrustAnchor -Zone '.' -keyTag 1 -Algorithm 13 -DigestType 2 -DigestHex 'AA'
			(Get-DnssecTrustedKey -Zone '.' -RootServers '192.0.2.1').Status | Should -Be 'Bogus'
		}

		It "authenticates a child zone through a parent-signed DS and a DS-matched, self-signed DNSKEY" {
			$ksk = $script:kskKey
			$ds = Get-DsRr $ksk 'example.com'
			$dsSig = Get-SigRr $script:rootKey $ds ''
			$kskRr = Get-KeyRr $ksk 'example.com'
			$kskSig = Get-SigRr $ksk $kskRr 'example.com'
			$script:dsPacket = Get-AnswerPacket @($ds, $dsSig)
			$script:keyPacket = Get-AnswerPacket @($kskRr, $kskSig)
			Mock Resolve-DnsIterative {
				if ($Type -eq 43) { [pscustomobject]@{ Status = 'Final'; Response = $script:dsPacket } }
				else { [pscustomobject]@{ Status = 'Final'; Response = $script:keyPacket } }
			}
			$r = Get-DnssecTrustedKey -Zone 'example.com' -RootServers '192.0.2.1'
			$r.Status | Should -Be 'Secure'
			@($r.Dnskeys).Count | Should -Be 1
		}

		It "is Bogus when the DS digest does not match the child's DNSKEY" {
			$ksk = $script:kskKey
			$ds = Get-DsRr $ksk 'example.com' -WrongDigest
			$dsSig = Get-SigRr $script:rootKey $ds ''
			$kskRr = Get-KeyRr $ksk 'example.com'
			$script:dsPacket = Get-AnswerPacket @($ds, $dsSig)
			$script:keyPacket = Get-AnswerPacket @($kskRr, (Get-SigRr $ksk $kskRr 'example.com'))
			Mock Resolve-DnsIterative {
				if ($Type -eq 43) { [pscustomobject]@{ Status = 'Final'; Response = $script:dsPacket } }
				else { [pscustomobject]@{ Status = 'Final'; Response = $script:keyPacket } }
			}
			(Get-DnssecTrustedKey -Zone 'example.com' -RootServers '192.0.2.1').Status | Should -Be 'Bogus'
		}

		It "is Bogus when the DS RRset is not signed by the parent's key" {
			$ksk = $script:kskKey
			$ds = Get-DsRr $ksk 'example.com'
			$stranger = Get-ChainKey
			$script:dsPacket = Get-AnswerPacket @($ds, (Get-SigRr $stranger $ds ''))
			$kskRr = Get-KeyRr $ksk 'example.com'
			$script:keyPacket = Get-AnswerPacket @($kskRr, (Get-SigRr $ksk $kskRr 'example.com'))
			Mock Resolve-DnsIterative {
				if ($Type -eq 43) { [pscustomobject]@{ Status = 'Final'; Response = $script:dsPacket } }
				else { [pscustomobject]@{ Status = 'Final'; Response = $script:keyPacket } }
			}
			(Get-DnssecTrustedKey -Zone 'example.com' -RootServers '192.0.2.1').Status | Should -Be 'Bogus'
		}

		It "treats a delegation whose only DS uses an unsupported algorithm as Insecure, not Bogus" {
			$ksk = $script:kskKey
			$ds = Get-DsRr $ksk 'example.com' -Algorithm 16
			$script:dsPacket = Get-AnswerPacket @($ds, (Get-SigRr $script:rootKey $ds ''))
			Mock Resolve-DnsIterative { [pscustomobject]@{ Status = 'Final'; Response = $script:dsPacket } }
			(Get-DnssecTrustedKey -Zone 'example.com' -RootServers '192.0.2.1').Status | Should -Be 'Insecure'
		}

		It "treats a delegation whose only DS uses an unsupported digest type as Insecure" {
			$ksk = $script:kskKey
			$ds = Get-DsRr $ksk 'example.com' -DigestType 3
			$script:dsPacket = Get-AnswerPacket @($ds, (Get-SigRr $script:rootKey $ds ''))
			Mock Resolve-DnsIterative { [pscustomobject]@{ Status = 'Final'; Response = $script:dsPacket } }
			(Get-DnssecTrustedKey -Zone 'example.com' -RootServers '192.0.2.1').Status | Should -Be 'Insecure'
		}

		It "uses the enclosing zone, not just the next label up, as the parent" {
			$ksk = $script:kskKey
			$ds = Get-DsRr $ksk 'a.b.example.com'
			$script:dsPacket = Get-AnswerPacket @($ds, (Get-SigRr $script:rootKey $ds ''))
			$script:asked = New-Object System.Collections.Generic.List[string]
			# b.example.com is NOT a zone; the enclosing zone of a.b.example.com is the root here
			Mock Test-DnsZoneApex { $false }
			Mock Resolve-DnsIterative {
				$script:asked.Add("$Name/$Type")
				if ($Type -eq 43) { [pscustomobject]@{ Status = 'Final'; Response = $script:dsPacket } }
				else { [pscustomobject]@{ Status = 'Final'; Response = (Get-AnswerPacket @()) } }
			}
			$null = Get-DnssecTrustedKey -Zone 'a.b.example.com' -RootServers '192.0.2.1'
			# the DS must have been checked against the ROOT keys: with the old one-label-up parent this would have asked for
			# b.example.com first (and returned Indeterminate); here the only DS lookup is for the zone itself
			$script:asked | Should -Contain 'a.b.example.com/43'
			$script:asked | Should -Not -Contain 'b.example.com/43'
		}

		It "treats a DS RRset signed with an unsupported algorithm as Insecure, not Bogus" {
			$ksk = $script:kskKey
			$ds = Get-DsRr $ksk 'example.com'
			$now = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
			$fake = [DnsResourceRecord]::new('example.com', 46, 1, 300, [byte[]]@(), [DnsRrsigRecord]::new(43, 16, 2, 300, ($now + 3600), ($now - 3600), 777, '', [byte[]](1..114)))
			$script:dsPacket = Get-AnswerPacket @($ds, $fake)
			Mock Resolve-DnsIterative { [pscustomobject]@{ Status = 'Final'; Response = $script:dsPacket } }
			(Get-DnssecTrustedKey -Zone 'example.com' -RootServers '192.0.2.1').Status | Should -Be 'Insecure'
		}

		It "ignores DNSKEY records that are not owned by the root when anchoring the root" {
			$rootRr = Get-KeyRr $script:rootKey ''
			$rootSig = Get-SigRr $script:rootKey $rootRr ''
			$other = Get-KeyRr (Get-ChainKey) 'evil.test'
			$script:rootPacket = Get-AnswerPacket @($rootRr, $other, $rootSig)
			$r = Get-DnssecTrustedKey -Zone '.' -RootServers '192.0.2.1'
			$r.Status | Should -Be 'Secure'
			@($r.Dnskeys).Count | Should -Be 1
		}
	}
}
