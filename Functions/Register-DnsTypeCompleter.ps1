Function Register-DnsTypeCompleter
{
	<#
		.SYNOPSIS
		Registers shared Tab completion for every function whose -Type parameter accepts either a DNS
		record type NAME (e.g. 'A', 'AAAA') or its numeric code, interchangeably.

		.DESCRIPTION
		2026-09-15. One registration point instead of duplicating the same completer scriptblock on
		each function's own -Type parameter - an inline [ArgumentCompleter(...)] attribute was tried
		first on Resolve-DnsIterative alone, then generalized here once ConvertTo-DnsTypeCode was found
		to have the exact same "name or code" contract (its own doc: "Accepts either a DNS record type
		name...or a numerical code") with no completion at all. ConvertFrom-DnsTypeCode and
		Format-DnsTypeName do NOT get this - their own -Type is strictly [int] (code only), so mnemonic
		completion would not apply.

		Called once, as a bare top-level statement at the bottom of this file, so it runs automatically
		when DnsTools.psm1 dot-sources every Functions\*.ps1 file at import time - no change needed to
		the generated psm1 or its tail script (Helpers\DnsTools-psm1-Tail.ps1).

		Suggests only the mnemonic NAMES (never numeric codes) for Tab completion, but does not
		restrict what can actually be typed - each function's own logic (ConvertTo-DnsTypeCode's
		"Unknown DNS record type: ..." check) still accepts a numeric code exactly as before.

		Reads $script:QtypeMap (Functions\Define-Variables.ps1, built by
		Helpers\Add-ReverseMapEntries.ps1) as the single source of truth for what type names exist -
		completion can never drift out of sync with what actually validates. QtypeMap is BIDIRECTIONAL
		(the same hashtable holds both 'A' -> 1 and 1 -> 'A'), so this filters to '-is [string]' keys
		only - a genuine Hashtable preserves each key's real .NET type, unlike a ValidateSetAttribute's
		own ValidValues collection, which stringifies everything (confirmed live 2026-09-15 while
		chasing exactly this bug - see Resolve-DnsIterative.ps1's own history/comments for the two
		false starts: ValidateSet+ArgumentCompleter together silently skip the completer for a bare Tab
		press on an empty word, and '-is [string]' does nothing against a stringified ValidValues list).

		PTR is intentionally included here (the earlier Resolve-DnsIterative-only version excluded it) -
		ConvertTo-DnsTypeCode is a general name/code converter where PTR is a perfectly normal value to
		convert, and Resolve-DnsIterative itself still has a real -IPAddr parameter (its own parameter
		set) that remains the encouraged, automatic way to do a PTR lookup - offering PTR as a
		completion here is a convenience for the less common case of asking for it directly through
		-Type, not a suggestion that it is the primary path.
	#>
	Register-ArgumentCompleter -CommandName 'Resolve-DnsIterative', 'ConvertTo-DnsTypeCode' -ParameterName 'Type' -ScriptBlock {
		param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)
		$script:QtypeMap.Keys |
			Where-Object { $_ -is [string] -and $_ -like "$WordToComplete*" } |
			Sort-Object |
			ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
	}
}

Register-DnsTypeCompleter
