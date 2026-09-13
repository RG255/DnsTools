# VENDORED from CommonScripts\0.2\Functions\Write-MyCatchAudit.ps1 by Sync-SharedUtilities [SHA256 849883A81DB5E18510996A6C454E79F67D5BF7D2FFD5490A28336715B6382552] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Write-MyCatchAudit
{
	<#
		.SYNOPSIS
		Records what triggered an accepted "best-effort" catch block, and optionally echoes it live.

		.DESCRIPTION
		Many catch blocks across these modules are deliberately empty or swallow their error - each one
		triaged and accepted in that module's `Tools\ErrorHandling-Baseline.psd1` entry for a SPECIFIC
		predicted failure (a cosmetic status update that may fail if a config is momentarily unreadable,
		a diagnostic fallback field that can safely default, teardown that must never throw). That
		triage answers "is this catch acceptable" ONCE, at review time - it cannot tell whether what
		actually lands there later is still that same predicted failure, or something different that
		happens to hit the same line. Calling this from inside such a catch closes that gap.

		2026-09-07, replaces VHDTools' Write-VHDCatchAudit and ConfigureDefender's Write-CDCatchAudit
		(both retired) with one shared, vendored version - the only thing that was ever genuinely
		module-specific about either (a per-module env-var name gating an opt-in toggle) goes away with
		this version, since CAPTURE is now unconditional (see below); what remains is exactly the shape
		of Get-MyError/Format-MyTextLine, already shared the same way.

		CAPTURE IS ALWAYS ON - every call appends a record to $Global:MyCatchAuditLog (a plain
		in-memory list, no I/O), regardless of any setting. This used to be opt-in
		($env:VHDCatchAuditEnabled et al) - a real incident (see memory project history) showed a
		genuinely non-repeatable, silent failure was lost forever because the toggle happened to be off
		at the time. $Global:, not $Script: - deliberately ONE shared trail across every module in the
		process, since a single user action often crosses module boundaries (e.g. a VHDTools operation
		calling into NamedPipe) and a fragmented per-module list would miss that.

		LIVE ECHO IS OPT-IN, via $env:MyCatchAuditVerbose = '1' (see Enable-MyCatchAudit/
		Disable-MyCatchAudit) - when set, ALSO writes a short, friendly report directly to
		[Console]::Error (a real OS console handle for the CURRENT process, unlike Write-Warning, which
		a calling context's own stream redirection - e.g. a GUI panel-op's `*>&1` merge - can silently
		swallow before it ever reaches a visible surface) and via Write-Warning (still the right,
		idiomatic signal for a plain script/console invocation, and what a GUI's own output-capturing
		wrapper still picks up). This is NOT the primary way to find out something was caught any more -
		see Show-MyCatchAuditSummary for that - it exists for "I am actively debugging right now, show
		me each one as it happens."

		CALLER LOCATION is captured automatically via Get-PSCallStack (the immediate caller - the real
		catch site - not $ErrorRecord.InvocationInfo, which points to where the underlying exception was
		originally RAISED and can genuinely differ). This replaces the old convention of manually typing
		a "FunctionName: " prefix into -Source, which silently goes stale the moment that function is
		renamed since nothing kept the two in sync. KNOWN LIMITATION, not solved by either approach: a
		catch site living inside an anonymous WPF event-handler scriptblock or `.GetNewClosure()` body
		reports its call-stack frame as literally `<ScriptBlock>`, not a useful name - a PowerShell
		limitation on anonymous scriptblocks, not something this function can fix. -Source's own text is
		what actually carries useful identification for those specific sites.

		-Source itself is UNCHANGED in purpose from the original per-module versions: free text, in the
		author's own words, for WHY this specific catch is accepted the way it is - a reminder for
		whoever reads it later. No mechanism can auto-derive that intent, so it stays mandatory.

		.PARAMETER Source
		Free-text reason this catch is accepted (e.g. 'Register-VHDChain: clear stale fingerprint - a
		missing/unreadable manifest here just means nothing to clear yet, not a real failure').

		.PARAMETER ErrorRecord
		The caught error - pass $_ from inside the Catch block.

		.PARAMETER Teardown
		2026-09-11. Pass this when the catch site lives inside a Finally/Dispose-style teardown block -
		code whose whole purpose is "must never throw, must complete no matter what" (e.g.
		Close-VHDPipeSession.ps1's Finally block). Capture (in-memory + persisted) is completely
		unaffected - it happens exactly the same either way. What changes is the live-echo tier: with
		-Teardown, live echo never fires, even if $env:MyCatchAuditVerbose is '1' - a deliberate extra
		safety margin, since teardown code's entire point is that nothing should risk interrupting it,
		not even the observability tooling that's supposed to be watching it. Also stamps IsTeardown on
		the record so a reviewer (Show-MyCatchAuditSummary, Invoke-MyCatchAuditTriage, or a raw read of
		the persisted log) can tell which entries came from teardown context after the fact.

		.EXAMPLE
		Catch { Write-MyCatchAudit -Source 'Register-VHDChain: clear stale fingerprint' -ErrorRecord $_ }

		.EXAMPLE
		Finally { Try { $Pipe.Dispose() } Catch { Write-MyCatchAudit -Source 'Close-VHDPipeSession: dispose pipe handle' -ErrorRecord $_ -Teardown } }

		.EXAMPLE
		Enable-MyCatchAudit
		# ... reproduce the issue - each accepted catch now also prints live ...
		Disable-MyCatchAudit

		.EXAMPLE
		Get-MyCatchAuditLog | Group-Object ExceptionType | Sort-Object Count -Descending
		# see which exception types are recurring across everything caught so far this process
	#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '',
		Justification = 'Deliberately process-wide, not per-module - one shared trail across every module in the process (see this function''s own DESCRIPTION for why $Script: would fragment it).')]
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory)]
		[String]$Source,
		[Parameter(Mandatory)]
		[System.Management.Automation.ErrorRecord]$ErrorRecord,
		[Switch]$Teardown
	)

	# Catch-auditing itself must never throw - it exists to make an accepted catch more visible, not
	# to introduce a NEW failure inside one (including inside a Finally/teardown block, where this is
	# just as safe to call as anywhere else - a plain in-memory append plus a self-guarded console
	# write cannot interrupt teardown).
	Try
	{
		$Private:_callerFrame = (Get-PSCallStack)[1]
		$Private:_callerLocation = If ($Private:_callerFrame)
		{ '{0} ({1})' -f $Private:_callerFrame.Command, $Private:_callerFrame.Location }
		Else { '<unknown caller>' }

		If (-not $Global:MyCatchAuditLog)
		{ $Global:MyCatchAuditLog = [System.Collections.Generic.List[PSCustomObject]]::new() }

		$Private:_exceptionTypeFull = $ErrorRecord.Exception.GetType().FullName
		$Private:_exceptionTypeName = $ErrorRecord.Exception.GetType().Name
		$Private:_scriptLeaf = Split-Path -Path $ErrorRecord.InvocationInfo.ScriptName -Leaf -ErrorAction SilentlyContinue
		# Short, stable per-entry ID (2026-09-10) - lets Invoke-MyCatchAuditTriage remove SPECIFIC
		# resolved entries from the persisted log without disturbing ones nobody has looked at yet.
		# Not used by the in-memory view at all (that is process-scoped and never individually pruned).
		$Private:_id = [Guid]::NewGuid().ToString('N').Substring(0, 8)

		$Private:_record = [PSCustomObject]@{
			Id             = $Private:_id
			Timestamp      = Get-Date
			Source         = $Source
			CallerLocation = $Private:_callerLocation
			ExceptionType  = $Private:_exceptionTypeFull
			Message        = $ErrorRecord.Exception.Message
			ScriptName     = $Private:_scriptLeaf
			LineNumber     = $ErrorRecord.InvocationInfo.ScriptLineNumber
			IsTeardown     = [Bool]$Teardown
		}
		$Global:MyCatchAuditLog.Add($Private:_record)

		# PERSIST (2026-09-10) - see Get-MyCatchAuditPersistPath's own doc for why and where. This is a
		# best-effort durability layer ON TOP of the in-memory capture above, which has already
		# succeeded by this point regardless of what happens here - a full disk, a locked-down
		# ProgramData, or any other write failure must never turn a successful catch-audit capture into
		# a thrown exception, so this has its own inner Try/Catch rather than relying on the outer one.
		Try
		{
			$Private:_persistPath = Get-MyCatchAuditPersistPath
			$Private:_jsonLine = [PSCustomObject]@{
				Id             = $Private:_id
				Timestamp      = $Private:_record.Timestamp.ToUniversalTime().ToString('o')
				Source         = $Source
				CallerLocation = $Private:_callerLocation
				ExceptionType  = $Private:_exceptionTypeFull
				Message        = $ErrorRecord.Exception.Message
				ScriptName     = $Private:_scriptLeaf
				LineNumber     = $ErrorRecord.InvocationInfo.ScriptLineNumber
				ProcessId      = $PID
				UserName       = [System.Environment]::UserName
				MachineName    = [System.Environment]::MachineName
				IsTeardown     = [Bool]$Teardown
			} | ConvertTo-Json -Compress -Depth 3
			Add-Content -LiteralPath $Private:_persistPath -Value $Private:_jsonLine -Encoding utf8 -ErrorAction Stop
		}
		Catch
		{
			# Not silent - but calling Write-MyCatchAudit to report ITS OWN persist step failing is
			# recursive by construction, so this checks the call stack first: if THIS is already a
			# recursive call (i.e. Write-MyCatchAudit already appears once below this frame, meaning
			# we got here by trying to report a PREVIOUS persist failure), stop recursing and fall back
			# to a direct Write-Warning instead - bounding the recursion to exactly one extra level
			# while still surfacing every failure, rather than silently swallowing the second one.
			$Private:_alreadyRecursing = @(Get-PSCallStack | Where-Object { $_.Command -eq 'Write-MyCatchAudit' }).Count -gt 1
			If ($Private:_alreadyRecursing)
			{ Write-Warning -Message ('Write-MyCatchAudit: could not persist a catch-audit entry, and the recursive report of that also failed to persist: {0}' -f $_.Exception.Message) }
			Else
			{ Write-MyCatchAudit -Source 'Write-MyCatchAudit: failed to persist a catch-audit entry to disk' -ErrorRecord $_ }
		}

		If (-not $Teardown -and $env:MyCatchAuditVerbose -eq '1')
		{
			$Private:_message = "CatchAudit :: {0}`n  at {1}`n  {2}: {3}`n  (error raised at {4}:{5})" -f
			$Source, $Private:_callerLocation, $Private:_exceptionTypeName, $Private:_record.Message,
			$Private:_scriptLeaf, $Private:_record.LineNumber

			Try { [Console]::Error.WriteLine($Private:_message) }
			# SILENT-OK: a process with no attached console (rare, but possible for some hosting
			# scenarios) would throw here; Write-Warning below is still attempted regardless.
			Catch { $null = $_ }

			Try { Write-Warning -Message $Private:_message }
			# SILENT-OK: same reasoning as above.
			Catch { $null = $_ }
		}
	}
	# SILENT-OK: catch-auditing itself must never throw.
	Catch { $null = $_ }
}
