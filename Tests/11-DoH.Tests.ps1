# Tests/11-DoH.Tests.ps1
# DNS-over-HTTPS (DoH) Transport Tests

using module dnstools

Describe "DnsDohClient - DNS-over-HTTPS Transport" {

    $fixtures = Join-Path $PSScriptRoot "Fixtures"

    It "Loads doh-simple-response.bin fixture" {
        $path = Join-Path $fixtures "doh-simple-response.bin"
        Test-Path $path | Should -BeTrue

        $bytes = [IO.File]::ReadAllBytes($path)
        $bytes.Length | Should -BeGreaterThan 0
    }

    It "Parses a DoH response using ConvertFrom-DnsWireBytes" {
        $path = Join-Path $fixtures "doh-simple-response.bin"
        $bytes = [IO.File]::ReadAllBytes($path)

        $pkt = ConvertFrom-DnsWireBytes -Bytes $bytes
        $pkt | Should -Not -BeNull
        $pkt.Answers.Count | Should -Be 1
        $pkt.Answers[0].RDataObject.Address | Should -Be "192.0.2.20"
    }

    Context "Simulated DoH Query" {

        # Fake DoH client that bypasses HTTP and returns fixture bytes
        class FakeDohClient {
            [byte[]] $ResponseBytes

            FakeDohClient([byte[]]$bytes) {
                $this.ResponseBytes = $bytes
            }

            [DnsPacket] Query([DnsPacket]$packet) {
                return ConvertFrom-DnsWireBytes -Bytes $this.ResponseBytes
            }
        }

        It "Returns a parsed DNS packet from a simulated DoH client" {
            $path = Join-Path $fixtures "doh-simple-response.bin"
            $bytes = [IO.File]::ReadAllBytes($path)

            $client = [FakeDohClient]::new($bytes)

            $query = [DnsPacket]::new()
            $query.Header = [DnsHeader]::new(4321, 0x0100, 1,0,0,0)
            $query.Questions.Add([DnsQuestion]::new("example.com", 1, 1))

            $resp = $client.Query($query)

            $resp.Answers.Count | Should -Be 1
            $resp.Answers[0].RDataObject.Address | Should -Be "192.0.2.20"
        }
    }

    Context "Error Handling" {

        It "Invoke-DnsTransportSafe wraps exceptions with context" {
            $script = {
                Invoke-DnsTransportSafe -Context "DoH test" -Operation {
                    throw "kaboom"
                }
            }

            { & $script } | Should -Throw -ErrorMessage "*DoH test failed: kaboom*"
        }
    }

    Context "Large DoH Response" {

        It "Parses doh-large-response.bin with multiple answers" {
            $path = Join-Path $fixtures "doh-large-response.bin"
            $bytes = [IO.File]::ReadAllBytes($path)

            $pkt = ConvertFrom-DnsWireBytes -Bytes $bytes

            $pkt.Answers.Count | Should -Be 5
            $pkt.Answers[0].RDataObject.Address | Should -Be "203.0.113.1"
            $pkt.Answers[4].RDataObject.Address | Should -Be "203.0.113.5"
        }
    }
}
