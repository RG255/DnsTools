# VENDORED from CommonScripts\0.2\Functions\Protect-MyFunctionTraceFolder.ps1 by Sync-SharedUtilities [SHA256 09A887EA35320A2C5C6B7532FEFF0E714C7740D511D5B3D84994B277A659E5E1] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Protect-MyFunctionTraceFolder
{
	<#
		.SYNOPSIS
		Locks down the function-trace log folder so other local users cannot read your trace logs - or, with
		-Check, reports whether it is locked down.

		.DESCRIPTION
		The trace facility writes its logs under <ProgramData>\FunctionTrace. A folder created there by an
		ordinary (non-elevated) process inherits ProgramData's defaults, which let EVERY local user read every
		log in it. Traced text can include paths, program names, timing and refusal reasons, so on a machine
		used by more than one account, lock the folder down once from an ELEVATED prompt:

		    SYSTEM, Administrators   full control (inherited by the log files)
		    Users                    this folder ONLY (not inherited): read+execute (list it) and add a file.
		                             No read of other people's logs, no subfolders. The names of other users'
		                             logs stay visible; their contents do not.
		    CREATOR OWNER            modify, inherited by new files - so each user keeps writing to, archiving
		                             and deleting their OWN logs

		An elevated pipe server running as an administrator can still write to the log its non-elevated client
		created (through the Administrators entry), so a client and its server keep sharing one file.

		RX (not just "list") is deliberate: opening a directory also needs SYNCHRONIZE and READ_ATTRIBUTES.
		Existing files are reset so they inherit the new ACL. Nothing is deleted or moved.

		Enable-MyFunctionTrace warns once when it sees the folder is not locked down. Set
		$env:MyFunctionTraceNoAclWarning = '1' to silence that (for example on a single-user machine).

		.PARAMETER Path
		The trace folder. Default: the folder Get-MyFunctionTracePath writes to.

		.PARAMETER Check
		Report only; change nothing and need no elevation.

		.PARAMETER FolderOnly
		With -Check: inspect just the folder, not each existing file (fast; used by Enable-MyFunctionTrace).

		.EXAMPLE
		Protect-MyFunctionTraceFolder            # apply, from an elevated prompt

		.EXAMPLE
		Protect-MyFunctionTraceFolder -Check     # is it locked down?

		.OUTPUTS
		[PSCustomObject] Path, LockedDown, Applied, Problems (and HiddenFiles: files owned by other accounts
		that this account cannot inspect - the intended protection, counted rather than hidden).
	#>
	[CmdletBinding(SupportsShouldProcess)]
	[OutputType([PSCustomObject])]
	Param (
		[String]$Path,
		[Switch]$Check,
		[Switch]$FolderOnly
	)

	If (-not $Path) { $Path = Split-Path -Path (Get-MyFunctionTracePath) -Parent }

	# Well-known SIDs, never account names (locale-proof): SYSTEM, Administrators, Users, CREATOR OWNER.
	$Private:_loose = @('S-1-5-32-545', 'S-1-1-0', 'S-1-5-11')
	$Private:_hidden = 0

	Function Get-TraceFolderProblem
	{
		Param ([String]$Folder, [Bool]$SkipFiles)
		$problems = New-Object Collections.Generic.List[String]
		If (-not (Test-Path -LiteralPath $Folder))
		{
			[void]$problems.Add('folder does not exist')
			Return @($problems)
		}
		$acl = Get-Acl -LiteralPath $Folder
		If (-not $acl.AreAccessRulesProtected) { [void]$problems.Add('inheritance from the parent folder is still enabled') }
		ForEach ($r in $acl.Access)
		{
			$sid = $null
			Try { $sid = $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } Catch { Continue }
			If ($Private:_loose -contains $sid -and $r.AccessControlType -eq 'Allow' -and ($r.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ObjectInherit))
			{ [void]$problems.Add(('{0} has an inheritable (file-level) allow entry: {1}' -f $r.IdentityReference.Value, $r.FileSystemRights)) }
		}
		If (-not $SkipFiles)
		{
			$exposed = 0
			ForEach ($f in @(Get-ChildItem -LiteralPath $Folder -File -Force))
			{
				$fa = $null
				Try { $fa = Get-Acl -LiteralPath $f.FullName }
				Catch
				{
					# A file whose ACL this account cannot even read is protected from this account - the
					# locked-down state, not a problem. Counted and reported; any other failure is real.
					If ($_.Exception -is [UnauthorizedAccessException]) { $Private:_hidden++; Continue }
					Throw
				}
				ForEach ($r in $fa.Access)
				{
					$sid = $null
					Try { $sid = $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } Catch { Continue }
					If ($Private:_loose -contains $sid -and $r.AccessControlType -eq 'Allow') { $exposed++; Break }
				}
			}
			If ($exposed -gt 0) { [void]$problems.Add(('{0} existing file(s) still readable by Users/Everyone/Authenticated Users' -f $exposed)) }
		}
		Return @($problems)
	}

	Try
	{
		If ($Check)
		{
			$Private:_p = @(Get-TraceFolderProblem -Folder $Path -SkipFiles ([Bool]$FolderOnly))
			Return [PSCustomObject]@{ Path = $Path; LockedDown = ($Private:_p.Count -eq 0); Applied = $false; Problems = $Private:_p; HiddenFiles = $Private:_hidden }
		}

		$Private:_isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
		If (-not $Private:_isAdmin)
		{
			Write-Error -Message 'Protect-MyFunctionTraceFolder needs an elevated PowerShell to change the ACL. Use -Check to only report.'
			Return [PSCustomObject]@{ Path = $Path; LockedDown = $false; Applied = $false; Problems = @('not elevated'); HiddenFiles = 0 }
		}

		If ($PSCmdlet.ShouldProcess($Path, 'Restrict the ACL so other local users cannot read the trace logs'))
		{
			If (-not (Test-Path -LiteralPath $Path)) { $null = New-Item -Path $Path -ItemType Directory -Force }
			& icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(RX,WD)' '*S-1-3-0:(OI)(IO)(M)' | Out-Null
			If ($LASTEXITCODE -ne 0) { Throw ('icacls failed on {0} (exit {1})' -f $Path, $LASTEXITCODE) }
			If (@(Get-ChildItem -LiteralPath $Path -File -Force).Count -gt 0)
			{ & icacls.exe (Join-Path -Path $Path -ChildPath '*') /reset /C /Q | Out-Null }
			$Private:_after = @(Get-TraceFolderProblem -Folder $Path -SkipFiles $false)
			Return [PSCustomObject]@{ Path = $Path; LockedDown = ($Private:_after.Count -eq 0); Applied = $true; Problems = $Private:_after; HiddenFiles = $Private:_hidden }
		}
		Return [PSCustomObject]@{ Path = $Path; LockedDown = $false; Applied = $false; Problems = @('-WhatIf: nothing changed'); HiddenFiles = 0 }
	}
	Catch
	{
		Write-MyCatchAudit -Source 'Protect-MyFunctionTraceFolder: locking down the trace folder' -ErrorRecord $_
		Throw
	}
}
