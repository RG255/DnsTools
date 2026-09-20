# VENDORED from CommonScripts\0.2\Functions\Get-MyError.ps1 by Sync-SharedUtilities [SHA256 F0DC7D6272EE74F74449E4D46C62F62266E71089F17115E2EA7D94ACB148FC10] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Get-MyError
{
	<#
		.SYNOPSIS
		Formats and optionally logs errors from the global error collection.

		.DESCRIPTION
		Processes the $Global:Error collection and formats each error with detailed
		information: line number, offset, exception message, stack trace, and other
		diagnostic details. Errors are formatted using Format-MyTextLine for
		consistent, readable output.

		By default, clears $Global:Error after processing. Use -PreserveErrors to
		keep the error collection intact.

		Bounded by default (2026-08-29, after a live incident: a long-lived elevated
		NamedPipe server's $Global:Error accumulated several benign, locally-caught
		errors across a multi-step operation; the next unrelated failure's report
		dumped the WHOLE collection with full stack traces, and that ballooning text
		fed into a downstream parameter-escaping call that hit OutOfMemoryException,
		taking the server process to 25GB+ before it was killed. See memory
		project_namedpipe_oom_error_cascade_2026_08_29 for the full incident). Only
		the MOST RECENT errors are formatted, each error's stack trace is capped, and
		a hard overall-length backstop applies regardless of the other two caps - so
		no caller can ever receive an unbounded report no matter how many errors, or
		how deep a single stack trace, feeds this. Existing callers get this for free
		with no changes; nothing relying on -Return output was relying on UNBOUNDED
		historical detail, only on what actually failed.

		.PARAMETER Indent
		Indentation level for error details. Default: 5.

		.PARAMETER Return
		When specified, returns the formatted error text as a string.
		Without this switch, errors are only logged (if PathToLogFile is set).

		.PARAMETER PreserveErrors
		When specified, does not clear $Global:Error after processing.

		.PARAMETER PathToLogFile
		Full path to the log file. If empty or null, logging is skipped.

		.PARAMETER MaxErrors
		Maximum number of MOST RECENT errors to format. Default: 10. The rest of
		$Global:Error is still cleared as normal (unless -PreserveErrors) - this only
		bounds how much gets FORMATTED/returned/logged in one call.

		.PARAMETER MaxStackTraceLength
		Maximum characters kept from each error's ScriptStackTrace. Default: 2000
		(normally 10-15 stack frames - enough to identify where something failed).
		Longer traces are truncated with a marker noting how much was cut.

		.PARAMETER MaxTotalLength
		Hard cap, in characters, on the total formatted output regardless of the two
		caps above. Default: 32768 (32KB). A backstop, not the primary control - the
		MaxErrors/MaxStackTraceLength defaults should normally stay well under this.

		.EXAMPLE
		Get-MyError -Return
		Returns the most recent errors (bounded) as a formatted string.

		.EXAMPLE
		Get-MyError -Return -PreserveErrors
		Returns errors as a formatted string without clearing the error collection.

		.EXAMPLE
		Get-MyError -Return -MaxErrors 25 -MaxStackTraceLength 5000
		Widens the caps for a deeper one-off diagnostic dump.

		.PARAMETER AsObject
		Returns one [PSCustomObject] per processed error instead of (or alongside - both switches are
		independent) the formatted text -Return produces. Added 2026-09-07 so a caller can actually
		DO something with a caught error programmatically (e.g. group a batch of captures by
		ExceptionType to spot which ones are genuinely recurring bugs) instead of parsing the text
		block back apart. Reuses the EXACT SAME extraction/transform/truncation as the text path (one
		pass over $Global:Error, not two) - the two outputs can never drift apart from each other, and
		-MaxErrors/-MaxStackTraceLength bound this path identically to the text path (MaxErrors already
		caps the COUNT of objects returned via the same loop control; MaxStackTraceLength caps the one
		field most likely to be unexpectedly huge, same as today). No separate total-size backstop is
		needed here the way -MaxTotalLength exists for the text path - a list of small, already
		field-capped objects cannot balloon into the same runaway-string shape the 2026-08-29 OOM
		incident hit, since there is no repeated padding/formatting overhead being concatenated.
		Object properties: Number, LineNo, Offset, Line, TargetObject, FullErrorId, Message,
		CommandPath, ExceptionType, FullErrorReason, StackTrace.

		.EXAMPLE
		Get-MyError -AsObject | Group-Object ExceptionType | Sort-Object Count -Descending
		Groups a batch of captured errors by exception type to see which ones recur most.

		.NOTES
		Version: 1.30 2026-09-15 - added automatic function-trace mirroring (see below).

		.OUTPUTS
		System.String - When -Return is specified, returns formatted error text.
		PSCustomObject[] - When -AsObject is specified, returns one object per processed error.

		2026-09-15: when function tracing is on (bit 1 of $env:MyFunctionTraceEnabled - see
		Enable-MyFunctionTrace's own doc, 2026-09-16), each processed error is ALSO mirrored as one
		line into the shared function-trace log (see Write-MyFunctionTrace/Get-MyFunctionTracePath), using
		the SAME field extraction/formatting (Format-MyFunctionTraceLine) so an error shows up inline, in
		timestamp order, alongside the call-flow lines that led to it - no separate opt-in flag, since
		there is no case where you'd want tracing on but errors excluded from that same timeline. This is
		purely additive to the existing -Return/-AsObject/-PathToLogFile outputs. Get-MyError itself is on
		the function-trace facility's permanent no-self-instrumentation exclusion list (see
		Write-MyFunctionTrace's own doc) - this mirroring code must never itself be traced.
	#>

	[CmdletBinding(PositionalBinding = $False)]
	Param (
		[Int]$Indent = [int]5,
		[Switch]$Return,
		[Switch]$AsObject,
		[Switch]$PreserveErrors,
		[String]$PathToLogFile = '',
		[Int]$MaxErrors = 10,
		[Int]$MaxStackTraceLength = 2000,
		[Int]$MaxTotalLength = 32768
	)

	# Whole-body wrap, added 2026-09-15 after a real incident: Get-MyError itself had NO outer
	# Try/Catch, so an internal formatting failure (a Format-MyTextLine call threw due to the
	# $env:MyFunctionTraceEnabled cross-contamination bug fixed the same day) propagated straight OUT
	# of the very function every module's catch blocks call to safely REPORT an error - killing the
	# caller's script mid-cleanup (confirmed live: a VHDTools mount session left VHDs mounted instead
	# of dismounting them, because the exception that would normally have been reported and handled
	# instead aborted the whole script before its Finally-based dismount logic ran). Get-MyError's
	# entire purpose is to degrade gracefully when something has already gone wrong - it must never
	# ITSELF become the thing that makes a bad situation catastrophic. Any internal failure here is
	# caught and sent to Write-MyCatchAudit (so it is still recorded, just not fatal to the caller).
	Try
	{
		$Private:ParamLen       = $Indent + 18
		$Private:NumberOfErrors = [int]$Global:Error.Count
		$Private:ErrorsToShow   = [Math]::Min($Private:NumberOfErrors, [Math]::Max($MaxErrors, 0))
		$Private:ErrorNumber    = $Private:NumberOfErrors - 1
		$Local:InternalError    = $True
		$Private:Err            = [System.Text.StringBuilder]''
		$Private:Objects        = [System.Collections.Generic.List[PSCustomObject]]::new()
		$Private:Shown          = [int]0
		$Private:LengthCapped   = $False

		$Private:Params = @{
			IndentLen  = $Indent
			ParamLen   = $Private:ParamLen
			ParamTrail = ': '
		}

		# Property mapping table. PropName is the object-safe identifier used ONLY by -AsObject (Name is
		# the human-readable label used ONLY by the text path) - kept as separate keys so neither path's
		# needs constrain the other's wording.
		$Private:PropertyMap = @(
			@{ Name = 'Line No.';          PropName = 'LineNo';          Path = 'InvocationInfo.ScriptLineNumber' }
			@{ Name = 'Offset';            PropName = 'Offset';          Path = 'InvocationInfo.OffsetInLine' }
			@{ Name = 'Line';              PropName = 'Line';            Path = 'InvocationInfo.Line' }
			@{ Name = 'Target Object';     PropName = 'TargetObject';    Path = 'TargetObject' }
			@{ Name = 'Full Error ID';     PropName = 'FullErrorId';     Path = 'FullyQualifiedErrorId' }
			@{ Name = 'Message';           PropName = 'Message';         Path = 'Exception.Message'; Transform = { $_.Replace("`r`n", '') } }
			@{ Name = 'Command Path';      PropName = 'CommandPath';     Path = 'InvocationInfo.PSCommandPath' }
			@{ Name = 'Exception Type';    PropName = 'ExceptionType';   Path = 'Exception'; Transform = { $_.GetType().FullName } }
			@{ Name = 'Full Error Reason'; PropName = 'FullErrorReason'; Path = 'FullyQualifiedErrorId'; Transform = { ($_ -split ',')[0] } }
			@{ Name = 'Stack Trace';       PropName = 'StackTrace';      Path = 'ScriptStackTrace' }
		)

		$Private:Number = [int]1

		# Function-trace mirroring (2026-09-15) - captured ONCE here (not per-error below), dropping this
		# function's own frame so Format-MyFunctionTraceLine sees index 0 as Get-MyError's CALLER, exactly
		# the same "one level in" relationship Write-MyFunctionTrace uses for a plain call-entry line.
		# SILENT-OK if this fails to set up: mirroring is a bonus output, never allowed to affect the error
		# processing this function exists to do.
		$Private:_traceStack = $null
		If (1 -band ($env:MyFunctionTraceEnabled -as [Int]))
		{
			Try
			{
				$Private:_fullStack = @(Get-PSCallStack)
				If ($Private:_fullStack.Count -ge 2)
				{ $Private:_traceStack = $Private:_fullStack[1..($Private:_fullStack.Count - 1)] }
			}
			Catch { $Private:_traceStack = $null }
		}

		While (([int]$Private:ErrorNumber -ge [int]0) -and ($Private:Shown -lt $Private:ErrorsToShow) -and (-not $Private:LengthCapped))
		{
			$Private:CurrentError = $Global:Error[$Private:ErrorNumber]

			# Error header
			$null = $Private:Err.AppendLine((Format-MyTextLine -IndentLen 0 -ParamLen 9 -Parameter ("`r`nError No") -Text ('{0}' -f $Private:Number)))

			# Process each property from the mapping table. $Private:_objRecord accumulates the SAME
			# extracted/transformed/truncated values the text path below uses - built unconditionally (not
			# just when -AsObject is passed) so both output shapes always come from one single pass and can
			# never disagree with each other.
			$Private:_objRecord = [ordered]@{ Number = $Private:Number }
			foreach ($Private:Prop in $Private:PropertyMap)
			{
				$Private:Value = $Private:CurrentError
				foreach ($Private:Part in $Private:Prop.Path -split '\.')
				{
					if ($null -ne $Private:Value)
					{ $Private:Value = $Private:Value.$Private:Part }
				}

				if ($Private:Value)
				{
					# Bracket notation, not dot notation: only 3 of the 10 PropertyMap entries define a
					# Transform key, and $Private:Prop.Transform (dot notation) throws "The property
					# 'Transform' cannot be found on this object" for the other 7 under a caller's own
					# Set-StrictMode -Version Latest (e.g. DnsTools.psm1 sets this) - found live 2026-09-15
					# wiring Get-MyError into DnsTools for the first time. Bracket indexing on a Hashtable
					# returns $null for a missing key under StrictMode instead of throwing.
					if ($Private:Prop['Transform'])
					{ $Private:Value = $Private:Value | ForEach-Object $Private:Prop['Transform'] }

					$Private:Text = '{0}' -f $Private:Value
					# Cap each error's own stack trace independently - the single most likely field
					# to be unexpectedly huge (deep nested elevated-pipe call chains).
					if ($Private:Prop.Name -eq 'Stack Trace' -and $Private:Text.Length -gt $MaxStackTraceLength)
					{
						$Private:OmittedChars = $Private:Text.Length - $MaxStackTraceLength
						$Private:Text = '{0} ...(truncated, {1} more char(s))' -f $Private:Text.Substring(0, $MaxStackTraceLength), $Private:OmittedChars
					}

					$Private:_objRecord[$Private:Prop.PropName] = $Private:Text

					$null = $Private:Err.AppendLine((
							Format-MyTextLine -ErrorAction SilentlyContinue @Private:Params `
								-Parameter $Private:Prop.Name `
								-Text $Private:Text
						))
				}
			}
			$Private:Objects.Add([PSCustomObject]$Private:_objRecord)

			# Function-trace mirroring (2026-09-15) - see this function's own .NOTES. SILENT-OK: a mirroring
			# failure must never interrupt error processing itself.
			If ($Private:_traceStack)
			{
				Try
				{
					# Bracket notation - see the Transform fix above for why: ExceptionType/Message are only
					# added to $Private:_objRecord when that error actually had a non-empty value for them,
					# so dot notation on a genuinely absent key throws under a caller's Set-StrictMode.
					$Private:_traceLine = Format-MyFunctionTraceLine -CallStack $Private:_traceStack `
						-ErrorTag $Private:_objRecord['ExceptionType'] -ErrorMessage $Private:_objRecord['Message']
					Add-Content -LiteralPath (Get-MyFunctionTracePath) -Value $Private:_traceLine -Encoding utf8 -ErrorAction Stop
				}
				Catch { Write-MyCatchAudit -Source 'Get-MyError: mirror a processed error into the function-trace log' -ErrorRecord $_ }
			}

			# Handle internal errors during processing
			if ([int]$Global:Error.Count -gt $Private:NumberOfErrors -and $Local:InternalError)
			{
				$Private:NumberOfErrors = [int]$Global:Error.Count
				$Private:ErrorsToShow   = [Math]::Min($Private:NumberOfErrors, [Math]::Max($MaxErrors, 0))
				$Private:ErrorNumber    = [int]$Global:Error.Count - 2
				$Local:InternalError    = $False
				Write-MyLog -PathToLogFile $PathToLogFile -Message 'An error occurred processing the error collection'
			}
			else
			{ $Private:ErrorNumber-- }

			$Private:Number++
			$Private:Shown++

			# Hard backstop - stop regardless of MaxErrors/MaxStackTraceLength if the total is
			# already large. Checked AFTER appending the current entry so an in-progress entry is
			# never cut mid-property; the next iteration's loop condition then exits cleanly.
			if ($Private:Err.Length -ge $MaxTotalLength)
			{ $Private:LengthCapped = $True }

			# Add separator between errors
			if (([int]$Private:ErrorNumber -ge [int]0) -and ($Private:Shown -lt $Private:ErrorsToShow) -and (-not $Private:LengthCapped))
			{
				$Private:Params.ParamTrail = ''
				$Private:Params.IndentLen  = [int]0
				$null = $Private:Err.AppendLine((
						Format-MyTextLine @Private:Params `
							-InitialLF "`r`n" `
							-Parameter ('{0}' -f $(''.PadRight($Private:ParamLen).Replace(' ', '_'))) `
							-Text ''
					))
				$Private:Params.ParamTrail = ': '
				$Private:Params.IndentLen  = $Indent
			}
		}

		# Note when the report is not the full picture - either more errors existed than MaxErrors
		# allowed, or the hard length backstop cut the run short.
		if (($Private:NumberOfErrors -gt $Private:Shown) -or $Private:LengthCapped)
		{
			$null = $Private:Err.AppendLine((
					Format-MyTextLine -IndentLen 0 -ParamLen 9 -InitialLF "`r`n" -Parameter 'Note' `
						-Text ('Showing the {0} most recent of {1} error(s); older ones omitted{2}.' -f
						$Private:Shown, $Private:NumberOfErrors,
						$(If ($Private:LengthCapped) { ' (report length cap reached)' } Else { '' }))
				))
		}

		# Log errors if a log path is configured and errors exist
		if ($Private:NumberOfErrors -gt 0 -and -not [String]::IsNullOrWhiteSpace($PathToLogFile))
		{ Write-MyLog -PathToLogFile $PathToLogFile -Message $Private:Err.ToString() }

		if (-not $PreserveErrors)
		{ $Global:Error.Clear() }

		if ($Return)
		{ $Private:Err.ToString() }

		if ($AsObject)
		{ $Private:Objects.ToArray() }
	}
	Catch
	{
		Write-MyCatchAudit -Source 'Get-MyError: internal failure while formatting/reporting errors' -ErrorRecord $_
		# Best-effort: still honor -PreserveErrors' contract even on this failure path, but never let
		# a SECOND failure here escape either. Routed through Write-MyCatchAudit too (not a silent
		# swallow) for the same reason as the outer catch - $Global:Error.Clear() failing is extremely
		# unlikely, but "unlikely" is exactly the class of failure this whole session's standing
		# principle exists for: catch it, record it, never assume it can't happen.
		Try { if (-not $PreserveErrors) { $Global:Error.Clear() } }
		Catch { Write-MyCatchAudit -Source 'Get-MyError: clear $Global:Error on the internal-failure path' -ErrorRecord $_ }
		if ($Return) { '' }
		if ($AsObject) { @() }
	}
}
