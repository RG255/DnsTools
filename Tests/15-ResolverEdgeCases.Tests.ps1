# Tests/15-ResolverEdgeCases.Tests.ps1
# Iterative Resolver Edge Case Tests

using module dnstools

Describe "Iterative Resolver - Edge Case Handling" {

    $fixtures = Join-Path $PSScriptRoot "Fixtures"

    #
    # Helper: Load fixture and parse into DnsPacket
    #
    function Load-FixturePacket {
        param([string]$name)

        $path = Join-Path $fixtures $name
        Test-Path $path | Should -BeTrue

        $bytes = [IO.File]::ReadAllBytes($path)
        return [DnsPacket]::Parse($bytes)
    }

    #
    # Fake UDP transport that returns fixture packets
    #
    class FakeUdpTransport {
        [DnsPacket] $Packet

        FakeUdpTransport([DnsPacket]$pkt) {
            $this.Packet = $pkt
        }

        [byte[]] Query([string]$server, [byte[]]$query) {
            return $this.Packet.ToArray()
        }
    }

    #
    # Patch Invoke-DnsUdpQuery to use FakeUdpTransport
    #
    BeforeEach {
        Mock Invoke-DnsUdpQuery {
            param($Server, $Query)
            return $Script:FakeTransport.Query($Server, $Query)
        }
    }

    #
    # 1. Broken Glue
    #
    Context "Broken Glue Handling" {

        It "Ignores glue that does not match NS names" {
            $pkt = Load-FixturePacket "referral-broken-glue.bin"
            $Script:FakeTransport = [FakeUdpTransport]::new($pkt)

            $result = Resolve-DnsIterative -Name "broken.example" -Type 1 -RootServers @("192.0.2.1")

            $result.Status | Should -Be "BailOut"
            $result.Reason | Should -Match "no usable referrals"
        }
    }

    #
    # 2. Mismatched NS
    #
    Context "Mismatched NS Handling" {

        It "Fails when NS referral contains names with no glue and no resolvable addresses" {
            $pkt = Load-FixturePacket "referral-mismatched-ns.bin"
            $Script:FakeTransport = [FakeUdpTransport]::new($pkt)

            $result = Resolve-DnsIterative -Name "mismatch.example" -Type 1 -RootServers @("192.0.2.1")

            $result.Status | Should -Be "BailOut"
            $result.Reason | Should -Match "no usable referrals"
        }
    }

    #
    # 3. Empty Authority
    #
    Context "Empty Authority Handling" {

        It "Fails when authority section is empty" {
            $pkt = Load-FixturePacket "referral-empty-authority.bin"
            $Script:FakeTransport = [FakeUdpTransport]::new($pkt)

            $result = Resolve-DnsIterative -Name "empty.example" -Type 1 -RootServers @("192.0.2.1")

            $result.Status | Should -Be "BailOut"
            $result.Reason | Should -Match "no usable referrals"
        }
    }

    #
    # 4. Cyclic NS Referrals
    #
    Context "Cyclic NS Handling" {

        It "Detects NS referral cycles and bails out" {
            $pkt = Load-FixturePacket "referral-cyclic-ns.bin"
            $Script:FakeTransport = [FakeUdpTransport]::new($pkt)

            $result = Resolve-DnsIterative -Name "cycle.example" -Type 1 -RootServers @("192.0.2.1")

            $result.Status | Should -Be "BailOut"
            $result.Reason | Should -Match "cycle"
        }
    }

    #
    # 5. Truncated Packets
    #
    Context "Truncated Packet Handling" {

        It "Handles truncated packets by ignoring server and trying next" {
            # Build a truncated packet manually
            $bytes = [byte[]](1,2,3,4,5)  # invalid DNS packet
            $pkt = $null

            $Script:FakeTransport = [FakeUdpTransport]::new($pkt)

            Mock Invoke-DnsUdpQuery { return $bytes }

            $result = Resolve-DnsIterative -Name "trunc.example" -Type 1 -RootServers @("192.0.2.1")

            $result.Status | Should -Be "BailOut"
        }
    }

    #
    # 6. Server-Set Cycle Detection
    #
    Context "Server Set Cycle Detection" {

        It "Detects repeated server sets and bails out" {
            # Build a fake packet that always returns the same NS referral
            $pkt = Load-FixturePacket "referral-cyclic-ns.bin"
            $Script:FakeTransport = [FakeUdpTransport]::new($pkt)

            $result = Resolve-DnsIterative -Name "loop.example" -Type 1 -RootServers @("192.0.2.1")

            $result.Status | Should -Be "BailOut"
            $result.Reason | Should -Match "Server-set cycle"
        }
    }
}
