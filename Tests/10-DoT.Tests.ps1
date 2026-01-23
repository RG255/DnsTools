# Tests/10-DoT.Tests.ps1
# DNS-over-TLS (DoT) Transport Tests

using module dnstools

Describe "DnsDotClient - DNS-over-TLS Transport" {

    $fixtures = Join-Path $PSScriptRoot "Fixtures"

    It "Loads dot-simple-response.bin fixture" {
        $path = Join-Path $fixtures "dot-simple-response.bin"
        Test-Path $path | Should -BeTrue

        $bytes = [IO.File]::ReadAllBytes($path)
        $bytes.Length | Should -BeGreaterThan 0
    }

    It "Parses a DoT response using ConvertFrom-DnsWireBytes" {
        $path = Join-Path $fixtures "dot-simple-response.bin"
        $bytes = [IO.File]::ReadAllBytes($path)

        $pkt = ConvertFrom-DnsWireBytes -Bytes $bytes
        $pkt | Should -Not -BeNull
        $pkt.Answers.Count | Should -Be 1
        $pkt.Answers[0].RDataObject.Address | Should -Be "192.0.2.10"
    }

    Context "Simulated DoT Query" {

        # Fake DoT client that bypasses TLS and returns fixture bytes
        class FakeDotClient {
            [byte[]] $ResponseBytes

            FakeDotClient([byte[]]$bytes) {
                $this.ResponseBytes = $bytes
            }

            [DnsPacket] Query([DnsPacket]$packet) {
                return ConvertFrom-DnsWireBytes -Bytes $this.ResponseBytes
            }
        }

        It "Returns a parsed DNS packet from a simulated DoT client" {
            $path = Join-Path $fixtures "dot-simple-response.bin"
            $bytes = [IO.File]::ReadAllBytes($path)

            $client = [FakeDotClient]::new($bytes)

            $query = [DnsPacket]::new()
            $query.Header = [DnsHeader]::new(1234, 0x0100, 1,0,0,0)
            $query.Questions.Add([DnsQuestion]::new("example.com", 1, 1))

            $resp = $client.Query($query)

            $resp.Answers.Count | Should -Be 1
            $resp.Answers[0].RDataObject.Address | Should -Be "192.0.2.10"
        }
    }

    Context "Error Handling" {

        It "Invoke-DnsTransportSafe wraps exceptions with context" {
            $script = {
                Invoke-DnsTransportSafe -Context "DoT test" -Operation {
                    throw "boom"
                }
            }

            { & $script } | Should -Throw -ErrorMessage "*DoT test failed: boom*"
        }
    }

    Context "Large DoT Response" {

        It "Parses dot-large-response.bin with multiple answers" {
            $path = Join-Path $fixtures "dot-large-response.bin"
            $bytes = [IO.File]::ReadAllBytes($path)

            $pkt = ConvertFrom-DnsWireBytes -Bytes $bytes

            $pkt.Answers.Count | Should -Be 5
            $pkt.Answers[0].RDataObject.Address | Should -Be "203.0.113.1"
            $pkt.Answers[4].RDataObject.Address | Should -Be "203.0.113.5"
        }
    }
}
