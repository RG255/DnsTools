# VENDORED from CommonScripts\0.2\Functions\Format-MyTextLine.ps1 by Sync-SharedUtilities [SHA256 3580AB288843663D31BD71D221462FFA4219CD97E9AE7142185EC33DDAC50096] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Format-MyTextLine
{
	<#
		.SYNOPSIS
		Formats a line of text with optional parameter label and automatic word-wrapping.

		.DESCRIPTION
		Produces console-friendly output lines with aligned parameter labels and text.
		Automatically wraps long text to fit the window width, breaking at spaces or
		line-ending characters. Useful for building -Help output and status messages.

		.PARAMETER Text
		The text body to format and (optionally) wrap.

		.PARAMETER Parameter
		Optional label placed to the left of the text, padded to ParamLen characters.

		.PARAMETER ParamTrail
		Character(s) between the label and the text. Defaults to nothing.

		.PARAMETER InitialLF
		A CR, LF, or CRLF sequence prepended to the output. Must be one of those
		whitespace sequences or empty.

		.PARAMETER ParamLen
		Width reserved for the label column. Defaults to the label's own length.

		.PARAMETER IndentLen
		Number of spaces to indent the label. Defaults to 0.

		.PARAMETER SetWindowWidth
		Override the auto-detected window width. Set to 0 (default) to auto-detect.

		.PARAMETER NoWrap
		Suppress word-wrapping. The text is appended as-is after the label.

		.EXAMPLE
		Format-MyTextLine -Parameter '-help' -ParamLen 10 -InitialLF "`r`n" `
		                  -Text 'Will output this text.' -ParamTrail ': '

		Returns (preceded by CRLF):
		-help     : Will output this text.

		.OUTPUTS
		System.String - The formatted line.
	#>

	[CmdletBinding(PositionalBinding = $False)]
	Param (
		[Parameter(Mandatory = $True, HelpMessage = 'Please supply the string to process')]
		[AllowEmptyString()]
		[String]$Text,
		[String]$Parameter    = '',
		[String]$ParamTrail   = '',
		[ValidatePattern('(?:[\n]+?|[\r]+?|[\r][\n]+?|^$)')]
		[AllowEmptyString()]
		[String]$InitialLF    = '',
		[ValidateRange(0, [int]::MaxValue)]
		[int]$ParamLen        = [int]0,
		[ValidateRange(0, [int]::MaxValue)]
		[int]$IndentLen       = [int]0,
		[ValidateRange(0, [int]::MaxValue)]
		[int]$SetWindowWidth  = [int]0,
		[switch]$NoWrap
	)

	# -and (Get-Command...) guard, added 2026-09-15: this file is vendored into nearly every module,
	# including several (VHDTools, VaultTools, Macrium, InstalledInventory) that never vendor the trace
	# facility itself. $env:MyFunctionTraceEnabled is process-scoped, so it can be '1' in any of their
	# processes purely because an unrelated NamedPipe/DnsTools test session in the same shell turned it
	# on - confirmed live as a real VHDTools mount-session crash ("'Write-MyFunctionTrace' is not
	# recognized"). The env check alone doesn't prove the function exists; only Get-Command does.
	If ((1 -band ($env:MyFunctionTraceEnabled -as [Int])) -and (Get-Command -Name Write-MyFunctionTrace -ErrorAction SilentlyContinue)) { Write-MyFunctionTrace }

	# Whole-body wrap, added 2026-09-15 - same reasoning and same real incident as Get-MyError.ps1's own
	# wrap (see that file's comment for the full story): this function is called directly from dozens of
	# places across every module to build help/status text, not just through Get-MyError, and its word-
	# wrap/Substring arithmetic below has no protection at all - a pathological width/label-length
	# combination throwing here would propagate straight out of a "just format this line for display"
	# call and could abort whatever caller was mid-cleanup, exactly like the original incident. On
	# internal failure this falls back to an unwrapped, unpadded concatenation of the inputs rather than
	# nothing - a plain-looking line still beats losing the text entirely.
	Try
	{

	# ── Inner helper: find a safe line-break position ─────────────────────────
	# Split-MyLine deliberately NOT traced - called once per wrapped line inside a single
	# Format-MyTextLine call (up to many times for long help text), same per-item/stream-processing
	# helper exemption as Resolve-DnsIterative's Format-DnsRecord - Format-MyTextLine's own trace stamp
	# already establishes the call happened.
	Function Split-MyLine
	{
		[CmdletBinding(PositionalBinding = $False)]
		Param (
			[Parameter(Mandatory = $True, ValueFromPipeline = $True)]
			[String]$Text
		)

		Process
		{
		# Already fits - return full length
		if ($Text.Length -le $Maxlen)
		{ return $Text.Length }

		# Degenerate case (should not occur in practice)
		if ($Text.Length -le 0)
		{ return 1 }

		$SearchText = $Text.Substring(0, $Maxlen)

		# Check break candidates in priority order: CRLF > CR > LF > space
		$BreakPoints = @(
			@{ Char = "`r`n"; Pos = $SearchText.IndexOf("`r`n")    }
			@{ Char = "`r";   Pos = $SearchText.LastIndexOf("`r")   }
			@{ Char = "`n";   Pos = $SearchText.LastIndexOf("`n")   }
			@{ Char = ' ';    Pos = $SearchText.LastIndexOf(' ')    }
		)

		foreach ($BP in $BreakPoints)
		{
			if ($BP.Pos -gt 0 -and $BP.Pos -le $Maxlen)
			{
				# For CRLF use the IndexOf position (first occurrence)
				return $BP.Pos
			}
		}

		# No good break point - hard-break at max
		return $Maxlen
		} # end Process
	}

	# ── Determine effective window width ──────────────────────────────────────
	$Private:MyWWidth = [int]0

	if ($SetWindowWidth -gt 0)
	{ $Private:MyWWidth = $SetWindowWidth }
	else
	{
		# Try reading from the host's raw UI; fall back to no-wrap if unavailable
		try
		{ $Private:MyWWidth = (Get-Host).UI.RawUI.WindowSize.Width }
		catch
		{
			$Private:MyWWidth = 0
			Write-MyCatchAudit -Source 'Format-MyTextLine: read host RawUI window width - host does not support it (e.g. redirected/non-interactive), falls back to NoWrap' -ErrorRecord $_
		}
	}

	if ($Private:MyWWidth -le 0)
	{ $NoWrap = $True }

	# ── Column geometry ───────────────────────────────────────────────────────
	if (-not $ParamLen)
	{ $ParamLen = $Parameter.Length }

	$PadRight       = [Math]::Max($ParamLen - $IndentLen, 0)
	$ParamTrailLen  = $ParamTrail.Length
	$Maxlen         = $Private:MyWWidth - ($ParamLen + $ParamTrailLen)

	# If the label overflows its column, shrink the available text width
	if ($Parameter.Length -gt $ParamLen)
	{ $Maxlen -= ($Parameter.Length - $ParamLen) }

	# Require at least 20 characters for wrapped text to be meaningful
	$MinWindowWidth = $ParamLen + $ParamTrailLen + 20
	if ($MinWindowWidth -gt $Private:MyWWidth)
	{ $NoWrap = $True }

	# ── Build output string ───────────────────────────────────────────────────
	[String]$TextOut = ''
	$TextOut += ('{0}{1}{2}' -f ''.PadLeft($IndentLen), $Parameter.PadRight($PadRight), $ParamTrail)

	if ($NoWrap)
	{
		$TextOut += $Text
	}
	else
	{
		$Text = $Text.Trim()

		if ($Text.Length -le $Maxlen)
		{
			$TextOut += $Text
		}
		else
		{
			$Private:FirstLine = $True
			$Private:Pad       = ''.PadLeft($ParamLen + $ParamTrailLen)

			while ($Text.Length -gt $Maxlen)
			{
				$Position = $Text | Split-MyLine
				if ($Private:FirstLine)
				{
					$TextOut += $Text.Substring(0, $Position)
					$Private:FirstLine = $False
				}
				else
				{ $TextOut += ("`r`n{0}{1}" -f $Private:Pad, $Text.Substring(0, $Position)) }
				$Text = $Text.Substring($Position).TrimStart()
			}
			$TextOut += ("`r`n{0}{1}" -f $Private:Pad, $Text)
		}
	}

	# Prepend any requested line-ending and return
	('{0}{1}' -f $InitialLF, $TextOut)
	}
	Catch
	{
		Write-MyCatchAudit -Source 'Format-MyTextLine: internal failure formatting/wrapping a line' -ErrorRecord $_
		# Best-effort fallback: an unwrapped, unpadded line still beats losing the text entirely. Routed
		# through Write-MyCatchAudit too if even THIS fails (matches Get-MyError's own last-resort catch)
		# rather than a silent swallow - see this function's own top-of-body note on why.
		Try { ('{0}{1}{2}{3}' -f $InitialLF, $Parameter, $ParamTrail, $Text) }
		Catch { Write-MyCatchAudit -Source 'Format-MyTextLine: even the fallback formatting failed' -ErrorRecord $_; '' }
	}
}
