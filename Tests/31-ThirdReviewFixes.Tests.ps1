# Tests/31-ThirdReviewFixes.Tests.ps1
# Regression tests for the third 0.8 code review: forged anchor-signing chain, wildcard next-closer proof, literal wildcard
# owners, CNAME-terminus truncation, DS denial from the child zone, reply matching for error replies, DoH hardening.

using module dnstools

InModuleScope DnsTools {

	Describe "0.8 third review fixes" {

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

			function Get-ARr {
				param([string]$Owner)
				[DnsResourceRecord]::new($Owner, 1, 1, 300, [byte[]](192, 0, 2, 1), [DnsARecord]@{ Address = '192.0.2.1' })
			}

			function Get-CnameRr {
				param([string]$Owner, [string]$Target)
				$cn = [DnsCnameRecord]::new($Target)
				[DnsResourceRecord]::new($Owner, 5, 1, 300, $cn.ToWire(), $cn)
			}

			function Get-NegativeResponse {
				param([uint16]$Rcode, [object[]]$Authority)
				$p = [DnsPacket]::new()
				$p.Header = [DnsHeader]::new(1, [uint16](0x8400 -bor $Rcode), 1, 0, [uint16]$Authority.Count, 0)
				foreach ($a in $Authority) { $null = $p.Authority.Add($a) }
				$p
			}

			function Get-ThumbprintHex {
				param($Cert)
				$sha = [System.Security.Cryptography.SHA256]::Create()
				try { [BitConverter]::ToString($sha.ComputeHash($Cert.RawData)).Replace('-', '') } finally { $sha.Dispose() }
			}
		}

		BeforeEach {
			Mock Write-MyCatchAudit { }
		}

		Context "Anchor-signing certificate chain" {

			BeforeAll {
				$nb = [DateTimeOffset]::UtcNow.AddDays(-1)
				$na = [DateTimeOffset]::UtcNow.AddDays(30)
				$rootKey = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
				$rootReq = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Test ICANN Root CA', $rootKey, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
				$rootReq.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
				$script:testRoot = $rootReq.CreateSelfSigned($nb, $na)

				$leafKey = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
				$leafReq = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Test Signer', $leafKey, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
				$script:goodLeaf = $leafReq.Create($script:testRoot, $nb, $na, [byte[]](1, 2, 3, 4))

				# The attack: the leaf CLAIMS the root as its issuer but is signed by the attacker's own key.
				$attackerKey = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
				$forgedReq = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Forged Signer', $leafKey, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
				$generator = [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForECDsa($attackerKey)
				$script:forgedLeaf = $forgedReq.Create($script:testRoot.SubjectName, $generator, $nb, $na, [byte[]](9, 9, 9, 9))
				$script:pin = Get-ThumbprintHex $script:testRoot
			}

			It "accepts a leaf that is really signed by the pinned root" {
				$r = Test-DnssecAnchorSignerChain -SignerCertificate $script:goodLeaf -ExtraCertificate @($script:testRoot) -PinnedRootThumbprint $script:pin
				$r.Valid | Should -BeTrue
			}

			It "rejects a forged leaf that only names the pinned root as its issuer" {
				$r = Test-DnssecAnchorSignerChain -SignerCertificate $script:forgedLeaf -ExtraCertificate @($script:testRoot) -PinnedRootThumbprint $script:pin
				$r.Valid | Should -BeFalse
			}

			It "rejects a chain that ends at a different root" {
				$r = Test-DnssecAnchorSignerChain -SignerCertificate $script:goodLeaf -ExtraCertificate @($script:testRoot) -PinnedRootThumbprint ('AA' * 32)
				$r.Valid | Should -BeFalse
				$r.Reason | Should -Match 'unexpected root'
			}

			It "rejects a signing certificate with no CA beside it" {
				(Test-DnssecAnchorSignerChain -SignerCertificate $script:goodLeaf -ExtraCertificate @() -PinnedRootThumbprint $script:pin).Valid | Should -BeFalse
			}
		}

		Context "Wildcard answers" {

			BeforeEach {
				$script:zk = Get-ZoneKey
				Mock Get-DnssecTrustedKey { [pscustomobject]@{ Status = 'Secure'; Reason = ''; Dnskeys = @($script:zk.Rr); DsRecords = @() } }
			}

			It "does not treat a queried literal wildcard owner (*.example.com) as an expansion" {
				$a = Get-ARr '*.example.com'
				$sig = Get-SignedRr $script:zk $a 'example.com' 2
				(Test-DnssecResponseSignature -Answers @($a, $sig)).Status | Should -Be 'Secure'
			}

			It "requires the NSEC to cover the NEXT CLOSER name, not the whole owner" {
				# wildcard *.example.com expanded to x.y.example.com; y.example.com exists, so no wildcard should apply.
				$a = Get-ARr 'x.y.example.com'
				$sig = Get-SignedRr $script:zk $a 'example.com' 2
				# This NSEC (owner y.example.com) covers x.y.example.com, but y.example.com itself is its OWNER, i.e. it exists.
				$nsec = Get-NsecRr 'y.example.com' 'z.example.com' @(1, 46, 47)
				$auth = @($nsec, (Get-SignedRr $script:zk $nsec))
				(Test-DnssecResponseSignature -Answers @($a, $sig) -Authority $auth).Status | Should -Be 'Bogus'
			}

			It "accepts a proper expansion where the next closer name is covered" {
				$a = Get-ARr 'x.example.com'
				$sig = Get-SignedRr $script:zk $a 'example.com' 2
				$nsec = Get-NsecRr 'example.com' 'z.example.com' @(2, 6, 46, 47)
				$auth = @($nsec, (Get-SignedRr $script:zk $nsec))
				(Test-DnssecResponseSignature -Answers @($a, $sig) -Authority $auth).Status | Should -Be 'Secure'
			}
		}

		Context "CNAME chains cannot be cut short" {

			BeforeEach {
				$script:zk = Get-ZoneKey
				Mock Get-DnssecTrustedKey { [pscustomobject]@{ Status = 'Secure'; Reason = ''; Dnskeys = @($script:zk.Rr); DsRecords = @() } }
			}

			It "is not Secure when only the signed CNAME arrives and the rest is missing" {
				$cn = Get-CnameRr 'www.example.com' 'target.example.com'
				$cnSig = Get-SignedRr $script:zk $cn
				$resp = Get-NegativeResponse 0 @()
				$r = Test-DnssecResponseSignature -Answers @($cn, $cnSig) -Response $resp -QueryName 'www.example.com' -QueryType 1
				$r.Status | Should -Not -Be 'Secure'
			}

			It "is Secure when the chain ends in an authenticated NODATA" {
				$cn = Get-CnameRr 'www.example.com' 'target.example.com'
				$cnSig = Get-SignedRr $script:zk $cn
				$soa = Get-SoaRr
				$nsec = Get-NsecRr 'target.example.com' 'zzz.example.com' @(16, 46, 47)
				$resp = Get-NegativeResponse 0 @($soa, (Get-SignedRr $script:zk $soa), $nsec, (Get-SignedRr $script:zk $nsec))
				$r = Test-DnssecResponseSignature -Answers @($cn, $cnSig) -Response $resp -QueryName 'www.example.com' -QueryType 1
				$r.Status | Should -Be 'Secure'
			}

			It "is Secure when the chain ends in data of the queried type" {
				$cn = Get-CnameRr 'www.example.com' 'target.example.com'
				$a = Get-ARr 'target.example.com'
				$resp = Get-NegativeResponse 0 @()
				$r = Test-DnssecResponseSignature -Answers @($cn, (Get-SignedRr $script:zk $cn), $a, (Get-SignedRr $script:zk $a)) -Response $resp -QueryName 'www.example.com' -QueryType 1
				$r.Status | Should -Be 'Secure'
			}
		}

		Context "DS denial must come from the parent" {

			It "rejects a DS NODATA that arrives with the child zone's own SOA" {
				$script:zk = Get-ZoneKey
				Mock Get-DnssecTrustedKey { [pscustomobject]@{ Status = 'Secure'; Reason = ''; Dnskeys = @($script:zk.Rr); DsRecords = @() } }
				$soa = Get-SoaRr -Owner 'sub.example.com'
				$nsec = Get-NsecRr 'sub.example.com' 'zzz.sub.example.com' @(2, 6, 46, 47, 48)
				$resp = Get-NegativeResponse 0 @($soa, (Get-SignedRr $script:zk $soa 'sub.example.com'), $nsec, (Get-SignedRr $script:zk $nsec 'sub.example.com'))
				(Test-DnssecNegativeResponse -Response $resp -QueryName 'sub.example.com' -QueryType 43).Status | Should -Be 'Bogus'
			}
		}

		Context "Test-DnsReplyMatch with error replies" {

			BeforeAll {
				$script:q = [byte[]](New-DnsQueryPacket -name 'example.com' -type 1)
			}

			It "accepts a REFUSED reply with an empty question section" {
				$r = [byte[]]($script:q[0..11]); $r[2] = 0x80; $r[3] = 5; $r[4] = 0; $r[5] = 0
				Test-DnsReplyMatch -Query $script:q -Reply $r | Should -BeTrue
			}

			It "rejects an empty-question reply that claims success" {
				$r = [byte[]]($script:q[0..11]); $r[2] = 0x80; $r[3] = 0; $r[4] = 0; $r[5] = 0
				Test-DnsReplyMatch -Query $script:q -Reply $r | Should -BeFalse
			}

			It "rejects a reply with more than one question" {
				$r = [byte[]]$script:q.Clone(); $r[2] = $r[2] -bor 0x80; $r[5] = 2
				Test-DnsReplyMatch -Query $script:q -Reply $r | Should -BeFalse
			}
		}

		Context "DoH client" {

			It "refuses a non-https endpoint instead of sending the query in clear text" {
				$pkt = [DnsPacket]::Parse([byte[]](New-DnsQueryPacket -name 'example.com' -type 1))
				{ ([DnsDohClient]::new('http://example.com/dns-query')).Query($pkt) } | Should -Throw '*https*'
			}
		}
	}
}
