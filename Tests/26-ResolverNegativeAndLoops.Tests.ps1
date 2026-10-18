# Tests/26-ResolverNegativeAndLoops.Tests.ps1
# 0.8: authoritative negative answers are returned (not a "server-set cycle" BailOut), server faults move on to
# the next server, and CNAME / nameserver-name loops terminate.

using module dnstools

InModuleScope DnsTools {

	Describe "Resolver negative answers and loop limits" {

		BeforeAll {
			function Get-TestResponse {
				param([string]$QName, [uint16]$QType, [uint16]$Flags, [object[]]$Answers = @(), [object[]]$Authority = @())
				$p = [DnsPacket]::new()
				$p.Header = [DnsHeader]::new(1, $Flags, 1, [uint16]$Answers.Count, [uint16]$Authority.Count, 0)
				$null = $p.Questions.Add([DnsQuestion]::new($QName, $QType, 1))
				foreach ($a in $Answers) { $null = $p.Answers.Add($a) }
				foreach ($a in $Authority) { $null = $p.Authority.Add($a) }
				, $p.ToArray()
			}

			function Get-TestSoaRr {
				param([string]$Owner)
				$soa = [DnsSoaRecord]::new('ns.example.com', 'h.example.com', 1, 2, 3, 4, 5)
				[DnsResourceRecord]::new($Owner, 6, 1, 300, $soa.ToWire(), $soa)
			}

			function Get-TestCnameRr {
				param([string]$Owner, [string]$Target)
				$cn = [DnsCnameRecord]::new($Target)
				[DnsResourceRecord]::new($Owner, 5, 1, 300, $cn.ToWire(), $cn)
			}

			function Get-TestNsRr {
				param([string]$Owner, [string]$Target)
				$ns = [DnsNsRecord]::new($Target)
				[DnsResourceRecord]::new($Owner, 2, 1, 300, $ns.ToWire(), $ns)
			}
		}

		BeforeEach {
			Mock Write-MyCatchAudit { }
		}

		Context "Negative answers" {

			It "returns NXDOMAIN as a Final answer instead of a server-set cycle" {
				Mock Invoke-DnsUdpQuery {
					$q = [DnsPacket]::Parse($query).Questions[0]
					[byte[]](Get-TestResponse -QName $q.Name -QType $q.Type -Flags 0x8403 -Authority @(Get-TestSoaRr 'example.com'))
				}
				$r = Resolve-DnsIterative -Name 'nothere.example.com' -Type A -RootServers '192.0.2.1' -Raw
				$r.Status | Should -Be 'Final'
				$r.Negative | Should -Be 'NXDOMAIN'
				@($r.Response.Answers).Count | Should -Be 0
			}

			It "returns NODATA (NOERROR, SOA, no NS) as a Final answer" {
				Mock Invoke-DnsUdpQuery {
					$q = [DnsPacket]::Parse($query).Questions[0]
					[byte[]](Get-TestResponse -QName $q.Name -QType $q.Type -Flags 0x8400 -Authority @(Get-TestSoaRr 'example.com'))
				}
				$r = Resolve-DnsIterative -Name 'www.example.com' -Type TXT -RootServers '192.0.2.1' -Raw
				$r.Status | Should -Be 'Final'
				$r.Negative | Should -Be 'NODATA'
			}

			It "ignores glue for a name the referral does not name" {
				$script:contacted = New-Object System.Collections.Generic.List[string]
				Mock Invoke-DnsUdpQuery {
					$script:contacted.Add($server)
					$q = [DnsPacket]::Parse($query).Questions[0]
					if ($server -eq '192.0.2.1') {
						$good = [DnsResourceRecord]::new('ns.example.com', 1, 1, 300, [byte[]](192, 0, 2, 99), [DnsARecord]@{ Address = '192.0.2.99' })
						$evil = [DnsResourceRecord]::new('evil.test', 1, 1, 300, [byte[]](6, 6, 6, 6), [DnsARecord]@{ Address = '6.6.6.6' })
						$p = [DnsPacket]::new()
						$p.Header = [DnsHeader]::new(1, 0x8000, 1, 0, 1, 2)
						$null = $p.Questions.Add([DnsQuestion]::new($q.Name, $q.Type, 1))
						$null = $p.Authority.Add((Get-TestNsRr 'example.com' 'ns.example.com'))
						$null = $p.Additional.Add($evil)
						$null = $p.Additional.Add($good)
						return , $p.ToArray()
					}
					$a = [DnsARecord]@{ Address = '203.0.113.7' }
					$rr = [DnsResourceRecord]::new($q.Name, 1, 1, 300, [byte[]](203, 0, 113, 7), $a)
					[byte[]](Get-TestResponse -QName $q.Name -QType $q.Type -Flags 0x8400 -Answers @($rr))
				}
				$r = Resolve-DnsIterative -Name 'www.example.com' -Type A -RootServers '192.0.2.1' -Raw
				$r.Status | Should -Be 'Final'
				$script:contacted | Should -Contain '192.0.2.99'
				$script:contacted | Should -Not -Contain '6.6.6.6'
			}

			It "generates unpredictable query IDs" {
				$ids = 1..300 | ForEach-Object { [DnsPacket]::Parse([byte[]](New-DnsQueryPacket -name 'example.com' -type 1)).Header.Id }
				@($ids | Sort-Object -Unique).Count | Should -BeGreaterThan 250
			}

			It "formats a signed negative answer (NSEC in authority) without throwing" {
				Mock Invoke-DnsUdpQuery {
					$q = [DnsPacket]::Parse($query).Questions[0]
					$n = [DnsNsecRecord]::new('next.example.com', [int[]](1, 28))
					$nsec = [DnsResourceRecord]::new('example.com', 47, 1, 300, $n.ToWire(), $n)
					[byte[]](Get-TestResponse -QName $q.Name -QType $q.Type -Flags 0x8403 -Authority @((Get-TestSoaRr 'example.com'), $nsec))
				}
				$r = Resolve-DnsIterative -Name 'nothere.example.com' -Type A -RootServers '192.0.2.1'
				$r.Status | Should -Be 'Success'
				$r.RCode | Should -Match 'NXDOMAIN'
			}

			It "does not treat SERVFAIL as an answer" {
				Mock Invoke-DnsUdpQuery {
					$q = [DnsPacket]::Parse($query).Questions[0]
					[byte[]](Get-TestResponse -QName $q.Name -QType $q.Type -Flags 0x8002)
				}
				$r = Resolve-DnsIterative -Name 'www.example.com' -Type A -RootServers '192.0.2.1' -Raw
				$r.Status | Should -Be 'BailOut'
			}

			It "still follows a referral (NS in authority, no SOA)" {
				$script:hop = 0
				Mock Invoke-DnsUdpQuery {
					$script:hop++
					$q = [DnsPacket]::Parse($query).Questions[0]
					if ($server -eq '192.0.2.1') {
						$glue = [DnsARecord]@{ Address = '192.0.2.99' }
						$g = [DnsResourceRecord]::new('ns.example.com', 1, 1, 300, [byte[]](192, 0, 2, 99), $glue)
						$p = [DnsPacket]::new()
						$p.Header = [DnsHeader]::new(1, 0x8000, 1, 0, 1, 1)
						$null = $p.Questions.Add([DnsQuestion]::new($q.Name, $q.Type, 1))
						$null = $p.Authority.Add((Get-TestNsRr 'example.com' 'ns.example.com'))
						$null = $p.Additional.Add($g)
						return , $p.ToArray()
					}
					$a = [DnsARecord]@{ Address = '203.0.113.7' }
					$rr = [DnsResourceRecord]::new($q.Name, 1, 1, 300, [byte[]](203, 0, 113, 7), $a)
					[byte[]](Get-TestResponse -QName $q.Name -QType $q.Type -Flags 0x8400 -Answers @($rr))
				}
				$r = Resolve-DnsIterative -Name 'www.example.com' -Type A -RootServers '192.0.2.1' -Raw
				$r.Status | Should -Be 'Final'
				$r.Response.Answers[0].RDataObject.Address | Should -Be '203.0.113.7'
			}
		}

		Context "Loop limits" {

			It "ends a CNAME loop with a BailOut instead of recursing forever" {
				$script:calls = 0
				Mock Invoke-DnsUdpQuery {
					$script:calls++
					$q = [DnsPacket]::Parse($query).Questions[0]
					$target = if ($q.Name -eq 'a.test') { 'b.test' } else { 'a.test' }
					[byte[]](Get-TestResponse -QName $q.Name -QType $q.Type -Flags 0x8400 -Answers @(Get-TestCnameRr $q.Name $target))
				}
				$r = Resolve-DnsIterative -Name 'a.test' -Type A -RootServers '192.0.2.1' -Raw
				$r.Status | Should -Be 'BailOut'
				$r.Reason | Should -Match 'CNAME chain'
				$script:calls | Should -BeLessThan 30
			}

			It "ends a mutually dependent nameserver-name loop" {
				$script:nsCalls = 0
				Mock Invoke-DnsUdpQuery {
					$script:nsCalls++
					$q = [DnsPacket]::Parse($query).Questions[0]
					$other = if ($q.Name -eq 'x.a.test') { 'y.b.test' } else { 'x.a.test' }
					$p = [DnsPacket]::new()
					$p.Header = [DnsHeader]::new(1, 0x8000, 1, 0, 1, 0)
					$null = $p.Questions.Add([DnsQuestion]::new($q.Name, $q.Type, 1))
					$null = $p.Authority.Add((Get-TestNsRr 'test' $other))
					, $p.ToArray()
				}
				$r = Resolve-NameserverAddress -nsName 'x.a.test' -BootstrapServers '192.0.2.1'
				$r | Should -BeNullOrEmpty
				$script:nsCalls | Should -BeLessThan 200
			}
		}
	}
}
