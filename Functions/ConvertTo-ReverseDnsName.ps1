function ConvertTo-ReverseDnsName {
    <#
    .SYNOPSIS
        Converts an IP address to its reverse DNS name format.

    .DESCRIPTION
        Converts IPv4 addresses to in-addr.arpa format and IPv6 addresses to ip6.arpa format.

    .PARAMETER IPAddress
        The IP address to convert.

    .EXAMPLE
        ConvertTo-ReverseDnsName -IPAddress '1.1.1.1'
        Returns: 1.1.1.1.in-addr.arpa

    .EXAMPLE
        ConvertTo-ReverseDnsName -IPAddress '2001:4860:4860::8888'
        Returns: 8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IPAddress
    )

    # Try to parse as IP address
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($IPAddress, [ref]$ip)) {
        # Not a valid IP address, return as-is
        return $IPAddress
    }

    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        # IPv4: reverse the octets and append in-addr.arpa
        $octets = $IPAddress.Split('.')
        [array]::Reverse($octets)
        return ($octets -join '.') + '.in-addr.arpa'
    }
    elseif ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        # IPv6: expand to full form, reverse nibbles, append ip6.arpa
        $bytes = $ip.GetAddressBytes()
        $nibbles = @()
        foreach ($byte in $bytes) {
            $nibbles += ('{0:x2}' -f $byte).ToCharArray()
        }
        [array]::Reverse($nibbles)
        return ($nibbles -join '.') + '.ip6.arpa'
    }

    # Unknown address family, return as-is
    return $IPAddress
}
