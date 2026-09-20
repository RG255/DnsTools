# VENDORED from CommonScripts\0.2\Functions\Invoke-FileManagement.ps1 by Sync-SharedUtilities [SHA256 67A43CA49BB95F7FA56DA0B25E29D7C5A606025E1D916F9BD1C44E09D6E3EF59] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Invoke-FileManagement
{
	<#
		.SYNOPSIS
		Manages files by age, count, or size with optional log rotation.

		.DESCRIPTION
		Deletes or rotates files matching a path pattern based on one of four rules:

		  DaysOld      - delete files older than N days
		  Number       - keep only the N most recent files
		  NumberAndDays - keep only the N most recent AND delete files older than N days
		  Size         - rotate log file when it exceeds MaxLogSizeBytes, keeping KeepCopies copies

		The rule is selected automatically based on which parameters are provided.

		.PARAMETER FilePath
		Path (or wildcard pattern) for the files to manage. Must resolve to at
		least one existing file.

		.PARAMETER DaysOld
		Delete files last written more than this many days ago. Default: 0 (disabled).

		.PARAMETER NumberOfFiles
		Keep no more than this many files. Default: 0 (disabled).

		.PARAMETER Size
		Rotate the file when it exceeds this many bytes (Size option). Default: 0 (disabled).

		.PARAMETER MaxLogSizeBytes
		Maximum file size in bytes before rotation (Size option). Default: 0.

		.PARAMETER KeepCopies
		Number of rotated copies to keep (Size option). Default: 5.

		.PARAMETER PathToLogFile
		Full path to the log file for deletion messages. Ignored if empty.

		.PARAMETER LogLevel
		Minimum log level to write deletion messages. Default: 0.

		.PARAMETER Encoding
		File encoding for log entries written during rotation. Default: UTF8.

		.EXAMPLE
		Invoke-FileManagement -FilePath 'C:\Logs\app*.log' -DaysOld 30

		.EXAMPLE
		Invoke-FileManagement -FilePath 'C:\Logs\app*.log' -NumberOfFiles 10

		.EXAMPLE
		Invoke-FileManagement -FilePath 'C:\Logs\app.log' -Size 1 -MaxLogSizeBytes 1048576 -KeepCopies 3
	#>

	[CmdletBinding(PositionalBinding = $False)]
	Param (
		[Parameter(Mandatory = $True, HelpMessage = 'Please supply file name or names!')]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
		[String]$FilePath,

		[Int]$DaysOld       = [int]0,
		[Int]$NumberOfFiles = [int]0,
		[Int]$Size          = [int]0,
		[Int]$MaxLogSizeBytes = [int]0,
		[Int]$KeepCopies    = [int]5,

		[String]$PathToLogFile = '',
		[Int]$LogLevel         = [int]0,
		[String]$Encoding      = 'UTF8'
	)

	if ($Size -gt [int]0)
	{ $Private:Option = 'Size' }
	elseif ($DaysOld -gt [int]0 -and $NumberOfFiles -gt [int]0)
	{ $Private:Option = 'NumberAndDays' }
	elseif ($DaysOld -gt [int]0)
	{ $Private:Option = 'DaysOld' }
	elseif ($NumberOfFiles -gt [int]0)
	{ $Private:Option = 'Number' }
	else
	{
		# Write-Error, NOT a bare string. This emitted the message to the SUCCESS stream, so a
		# caller writing '$Result = Invoke-FileManagement ...' received the ERROR TEXT as the
		# result - truthy, non-empty and indistinguishable from a real answer. Anything testing
		# 'if ($Result)' therefore treated a rejected call as a successful one.
		# The caller now gets $null plus a real error record. Vendored into every consumer, so
		# this shape was replicated everywhere.
		Write-Error 'Invoke-FileManagement: Size, DaysOld, NumberOfFiles, or a combination of DaysOld and NumberOfFiles must be greater than zero.'
		return
	}

	$Private:Dir = Split-Path -Path $FilePath -Parent

	switch ($Private:Option)
	{
		'DaysOld'
		{
			foreach ($Private:File in (Get-Item -Path $FilePath))
			{
				if ($Private:File.LastWriteTime.ToFileTimeUtc() -lt (Get-Date).AddDays(-$DaysOld).ToFileTimeUtc())
				{
					if (Test-Path -Path $Private:File.FullName)
					{
						if ([Environment]::UserInteractive)
						{ 'Deleting: {0}' -f $Private:File | Write-Output }
						try
						{ Remove-Item -Path $Private:File.FullName -ErrorAction Stop }
						catch
						{ Write-Warning ('Invoke-FileManagement: could not delete [{0}]: {1}' -f $Private:File.FullName, $_.Exception.Message)
						Write-MyCatchAudit -Source 'Invoke-FileManagement: delete one expired file (DaysOld rule) - best-effort housekeeping, one locked/undeletable file must not stop the rest' -ErrorRecord $_
					}
					}
				}
			}
		}

		'Number'
		{
			[Array]$Private:FileNames = (Get-Item -Path $FilePath).FullName | Sort-Object -Descending
			$Private:Count = [int]$Private:FileNames.Count - 1
			while ($Private:Count -gt $NumberOfFiles)
			{
				if (Test-Path -Path $Private:FileNames[$Private:Count])
				{
					if ($LogLevel -gt [int]0)
					{ 'Deleting: {0}' -f $Private:FileNames[$Private:Count] | Write-MyLog -PathToLogFile $PathToLogFile }
					try
					{ Remove-Item -Path $Private:FileNames[$Private:Count] -ErrorAction Stop }
					catch
					{ Write-Warning ('Invoke-FileManagement: could not delete [{0}]: {1}' -f $Private:FileNames[$Private:Count], $_.Exception.Message)
					Write-MyCatchAudit -Source 'Invoke-FileManagement: delete one excess file (Number rule) - best-effort housekeeping, one locked/undeletable file must not stop the rest' -ErrorRecord $_
				}
				}
				$Private:Count--
			}
		}

		'NumberAndDays'
		{
			$Private:FileNames = Get-Item -Path $FilePath | Sort-Object -Descending
			$Private:Count     = [int]$Private:FileNames.Count
			while ($Private:Count -gt $NumberOfFiles)
			{
				$Private:Date    = $Private:FileNames.LastWriteTime[$Private:Count - 1].ToFileTimeUtc()
				$Private:DelFile = Join-Path $Private:Dir $Private:FileNames.Name[$Private:Count - 1]
				if ($Private:Date -lt (Get-Date).AddDays(-$DaysOld).ToFileTimeUtc())
				{
					if (Test-Path -Path $Private:DelFile)
					{
						if ([Environment]::UserInteractive)
						{ 'Deleting: {0}' -f $Private:DelFile | Write-Output }
						try
						{ Remove-Item -Path $Private:DelFile -ErrorAction Stop }
						catch
						{ Write-Warning ('Invoke-FileManagement: could not delete [{0}]: {1}' -f $Private:DelFile, $_.Exception.Message)
						Write-MyCatchAudit -Source 'Invoke-FileManagement: delete one expired-and-excess file (NumberAndDays rule) - best-effort housekeeping, one locked/undeletable file must not stop the rest' -ErrorRecord $_
					}
					}
				}
				$Private:Count--
			}
		}

		'Size'
		{
			if ((Test-Path -Path $FilePath) -and (Get-Item -Path $FilePath).Length -gt $MaxLogSizeBytes)
			{
				$Private:CDate  = (Get-Date -Date (Get-Item -Path $FilePath).CreationTime -Format 'yyyyMMdd_HHmmss')
				$Private:Parent = Split-Path -Parent -Path $FilePath
				$Private:Name   = (Split-Path -Leaf -Path $FilePath).Split('.')[0]
				$Private:Ext    = (Split-Path -Leaf -Path $FilePath).Split('.')[1]
				$Private:Files  = Get-Item -Path ($Private:Parent + '\' + $Private:Name + '*' + $Private:Ext)

				while ($Private:Files.Count -gt $KeepCopies)
				{
					if (Test-Path -Path $Private:Files[1].FullName)
					{
						try
						{
							Out-File -Encoding $Encoding -FilePath $FilePath -Append -InputObject (
								(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' Old Log File deleted: [' + $Private:Files[1].Name + ']')
							if ([Environment]::UserInteractive)
							{ $Private:Files[1].FullName | Write-Output }
							Remove-Item -Path $Private:Files[1].FullName -ErrorAction Stop
						}
						catch
						{ Write-Warning ('Invoke-FileManagement: could not delete [{0}]: {1}' -f $Private:Files[1].FullName, $_.Exception.Message)
						Write-MyCatchAudit -Source 'Invoke-FileManagement: delete one rotated-out log copy (Size rule) - best-effort housekeeping, one locked/undeletable file must not stop rotation' -ErrorRecord $_
					}
						$Private:Files = Get-Item -Path ($Private:Parent + '\' + $Private:Name + '*' + $Private:Ext)
					}
				}

				$Private:NewName = $Private:Parent + '\' + $Private:Name + '_' + $Private:CDate + '.' + $Private:Ext
				try
				{
					Move-Item -Path $FilePath -Destination $Private:NewName -ErrorAction Stop
					Out-File -Encoding $Encoding -FilePath $FilePath -Append -InputObject (
						(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + (' New log created, old log renamed to: [{0}]' -f $Private:NewName))
				}
				catch
				{ Write-Warning ('Invoke-FileManagement: log rotation failed for [{0}]: {1}' -f $FilePath, $_.Exception.Message)
					Write-MyCatchAudit -Source 'Invoke-FileManagement: rename the current log to its rotated name and start a new one (Size rule) - a failure here leaves the log unrotated but does not lose the existing file' -ErrorRecord $_
				}
			}
		}
	}
}
