# Tests/16-TransportHelpers.Tests.ps1
# Transport Helper Function Tests

using module dnstools

Describe "Transport Helper Functions" {

    Context "ConvertTo-DnsWireBytes" {

        It "Serializes a simple DNS query into wire format" {
            $pkt = [DnsPacket]::new()
            $pkt.Header = [DnsHeader]::new(0x1111, 0x0100, 1,0,0,0)
            $pkt.Questions.Add([DnsQuestion]::new("example.com", 1, 1))

            $bytes = ConvertTo-DnsWireBytes -Packet $pkt

            $bytes | Should -Not -BeNull
            $bytes.Length | Should -BeGreaterThan 12  # header + question
        }

        It "Produces deterministic output for identical packets" {
            $pkt1 = [DnsPacket]::new()
            $pkt1.Header = [DnsHeader]::new(0x2222, 0x0100, 1,0,0,0)
            $pkt1.Questions.Add([DnsQuestion]::new("example.com", 1, 1))

            $pkt2 = [DnsPacket]::new()
            $pkt2.Header = [DnsHeader]::new(0x2222, 0x0100, 1,0,0,0)
            $pkt2.Questions.Add([DnsQuestion]::new("example.com", 1, 1))

            $b1 = ConvertTo-DnsWireBytes -Packet $pkt1
            $b2 = ConvertTo-DnsWireBytes -Packet $pkt2

            $b1 | Should -Be $b2
        }
    }

    Context "ConvertFrom-DnsWireBytes" {

        It "Parses a serialized DNS packet back into a DnsPacket object" {
            $pkt = [DnsPacket]::new()
            $pkt.Header = [DnsHeader]::new(0x3333, 0x0100, 1,0,0,0)
            $pkt.Questions.Add([DnsQuestion]::new("example.com", 1, 1))

            $bytes = ConvertTo-DnsWireBytes -Packet $pkt
            $parsed = ConvertFrom-DnsWireBytes -Bytes $bytes

            $parsed | Should -Not -BeNull
            $parsed.Header.Id | Should -Be 0x3333
            $parsed.Questions[0].Name | Should -Be "example.com"
        }

        It "Throws when given invalid DNS wire data" {
            $bytes = [byte[]](1,2,3,4,5)

            { ConvertFrom-DnsWireBytes -Bytes $bytes } | Should -Throw
        }
    }

    Context "Invoke-DnsTransportSafe" {

        It "Returns the result of a successful operation" {
            $result = Invoke-DnsTransportSafe -Context "test" -Operation {
                return 123
            }

            $result | Should -Be 123
        }

        It "Wraps exceptions with context" {
            $script = {
                Invoke-DnsTransportSafe -Context "transport" -Operation {
                    throw "boom"
                }
            }

            { & $script } | Should -Throw -ExpectedMessage "*transport failed: boom*"
        }

        It "Does not swallow exceptions" {
            $script = {
                Invoke-DnsTransportSafe -Context "x" -Operation {
                    throw "fail"
                }
            }

            { & $script } | Should -Throw
        }
    }
}
