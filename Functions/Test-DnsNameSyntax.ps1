function Test-DnsNameSyntax
{
	<#
		.SYNOPSIS
		Validates DNS name syntax, returning a structured pass/fail result instead of throwing.

		.DESCRIPTION
		2026-09-15. Moved out of Resolve-DnsIterative's own [ValidateScript(...)] attribute so an
		invalid name can be reported to the caller as a Status object (see Resolve-DnsIterative's own
		.DESCRIPTION) instead of a thrown ParameterBindingException - ValidateScript runs during
		PowerShell's own parameter-binding phase, before the function body (and its established "never
		throw, always return Status" convention) ever gets a turn.

		Enforces, in order:
		  - Name is not empty.
		  - Total length <=255 characters (RFC 1035) - NOT enforced by the previous ValidateScript
		    regex (confirmed live 2026-09-15: a name built from valid <=63-char labels but 258
		    characters overall passed it).
		  - Each label is 1-63 characters.
		  - No empty label (rejects a leading, trailing, or consecutive dot, e.g. "www..example.com" -
		    this WAS already correctly rejected by the previous regex; kept here for the same result).
		  - A label may start with ONE leading underscore (e.g. _sip, _dmarc, _domainkey,
		    _acme-challenge - the common SRV/TXT/DKIM/ACME-verification pattern) - not in strict
		    RFC 1035 but universally supported in practice, and NOT accepted by the previous regex
		    (confirmed live 2026-09-15: "_sip._tcp.example.com" failed it). Otherwise a label is
		    alphanumeric with optional internal hyphens, never leading or trailing.

		Does NOT auto-convert an internationalized (raw Unicode) name to punycode - a caller with an
		IDN must encode it themselves first (e.g. 'xn--caf-dma.com', not 'café.com'). This is an
		explicit, documented limitation carried over unchanged from the previous ValidateScript, not a
		new restriction - this function is a like-for-like port plus the two fixes above, not a
		broader redesign of what is or isn't an acceptable name.

		.PARAMETER Name
		The DNS name to validate. A single trailing dot (the root label) is permitted and ignored.

		.OUTPUTS
		[PSCustomObject] with IsValid ([bool]) and Reason ([string], empty when IsValid is $true).

		.EXAMPLE
		Test-DnsNameSyntax -Name 'www.example.com'
		IsValid = $true

		.EXAMPLE
		Test-DnsNameSyntax -Name 'www..example.com'
		IsValid = $false, Reason describing the empty label
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	Param (
		[Parameter(Mandatory)]
		[AllowEmptyString()]
		[string]$Name
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	$Private:Trimmed = $Name.TrimEnd('.')

	if ([string]::IsNullOrEmpty($Private:Trimmed)) {
		return [PSCustomObject]@{ IsValid = $false; Reason = 'DNS name cannot be empty.' }
	}
	if ($Name.Length -gt 255) {
		return [PSCustomObject]@{ IsValid = $false; Reason = "DNS name '$Name' exceeds the 255-character total length limit ($($Name.Length) characters)." }
	}

	foreach ($Private:Label in ($Private:Trimmed -split '\.')) {
		if ($Private:Label.Length -eq 0) {
			return [PSCustomObject]@{ IsValid = $false; Reason = "DNS name '$Name' contains an empty label (a leading, trailing, or consecutive dot)." }
		}
		if ($Private:Label.Length -gt 63) {
			return [PSCustomObject]@{ IsValid = $false; Reason = "DNS name '$Name' has a label ('$($Private:Label)') longer than 63 characters ($($Private:Label.Length) characters)." }
		}

		# One optional leading underscore for the SRV/TXT/DKIM/ACME-verification pattern (_sip, _dmarc,
		# _domainkey, _acme-challenge, ...) - the remainder must still look like a normal label.
		$Private:BareLabel = if ($Private:Label[0] -eq '_') { $Private:Label.Substring(1) } else { $Private:Label }
		if ($Private:BareLabel.Length -eq 0 -or $Private:BareLabel -notmatch '^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$') {
			return [PSCustomObject]@{ IsValid = $false; Reason = "DNS name '$Name' has an invalid label ('$($Private:Label)') - labels must be alphanumeric with optional internal hyphens (never leading/trailing), and may start with at most one underscore." }
		}
	}

	return [PSCustomObject]@{ IsValid = $true; Reason = '' }
}
