# In the following tables defining variables:
#
# Option can be one of the following: AllScope, Private, Constant, ReadOnly, None
# Scope  can be one of the following: Global, Local, Script , Using, Workflow
# See Microsoft documentation for full descriptions.
#
# To use the regular expressions below:
#
# Does the item your testing match the expresion:
#
# if (($RegexComment.Match($Item).Success)){'It is a comment'}else{'It is not a comment'}
#
# To get the item itself use the name defined in the expression:
#
# $Result = $RegexFile.Match($Item)
# $Length = $Result.Groups['file'].length - will return the length of the 'file' group
# $Entry = $Result.Groups['file'].value - will return the value of the 'file' group
#
# Alternativly you can use:
#
# If ($Item -match $RegexFile)
# {$matches['file']} # to display the item if a match is found
#
# Both ways return different attributes it depends how you want to use the results
#
# NOTE: To get the captured group information the name is case sensitive.
#'file' is OK but 'File' is not!
#
# Add variables that you can use later in the 'MyConstantVars' hash table
#
# Variables defined in the 'MyOtherVars' hashtable can make use of the variables defined above
# in the 'MyConstantVars' or 'MyReadOnlyVars' hashtable
#
# NOTE: If any variables are defined in 'MyConstantVars' you will not be able to force a
# reload of the module, you will have to start a new PowerShell session.
#
# The option on the constant Variables is reda only to make testing easier
#
$MyVars = [Ordered]@{
	N00ConstantVars = @{
		VOConstant = @{
			Value  = 'Constant'
			Scope  = 'Script'
			Option = 'ReadOnly'
		}
	}
}
Publish-Variables
$MyVars = [Ordered]@{
	N00ConstantVars = @{
		VInfoOn    = @{
			Value  = $True
			Scope  = 'Script'
			Option = 'ReadOnly'
			Use    = 'Define Variables Information'
		}
		FInfoOn    = @{
			Value  = $True
			Scope  = 'Script'
			Option = 'ReadOnly'
			Use    = 'Define Common Functions Information'
		}
		FWInfoOn   = @{
			Value  = $True
			Scope  = 'Script'
			Option = 'ReadOnly'
			Use    = 'Define Windows Functions Information'
		}
		FLInfoOn   = @{
			Value  = $False
			Scope  = 'Script'
			Option = 'ReadOnly'
			Use    = 'Define Linux Functions Information'
		}
		FMInfoOn   = @{
			Value  = $False
			Scope  = 'Script'
			Option = 'ReadOnly'
			Use    = 'Define MacOS Functions Information'
		}
		VSScript   = @{
			Value  = 'Script'
			Scope  = 'Script'
			Option = 'ReadOnly'
		}
		VOReadOnly = @{
			Value  = 'ReadOnly'
			Scope  = 'Script'
			Option = 'ReadOnly'
		}
	}
}
Publish-Variables
$MyVars = @{
	N01ReadOnlyVars = @{
		VSGlobal   = @{
			Value  = 'Global'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		VSUsing    = @{
			Value  = 'Using'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		VSWorkFlow = @{
			Value  = 'WorkFlow'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		VOAllScope = @{
			Value  = 'AllScope'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		VOPrivate  = @{
			Value  = 'Private'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		VONone     = @{
			Value  = 'None'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
	}
}
Publish-Variables

If (-Not $ModuleLoaded)
{
	$ML = @{}
	$ML.$ModuleName = @{
		Name = $ModuleName
		Path = $ModuleScriptRoot
	}		
}
ElseIf (-not $ML.$ModuleName)
{
	$ML.$ModuleName += @{
		Name = $ModuleName
		Path = $ModuleScriptRoot
	}
}

$MyVars = @{
	N02ReadOnlyVars = @{
		ModuleVersion          = @{
			Value  = $PSD1Data.ModuleVersion
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		MajorPSVersion         = @{
			Value  = [String]($PSVersionTable.PSVersion.Major)
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		ModuleLoaded           = @{
			Value  = $ML
			Scope  = $VSScript
			Option = $VONone
		}
		Administrator          = @{
			Value  = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		Interactive            = @{
			Value  = [Environment]::UserInteractive
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		MyCulture              = @{
			Value  = [cultureinfo]::GetCultures('Allcultures') | Where-Object -Property name -imatch (Get-Culture).name
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrInvalidCharacters   = @{
			Value  = [string]'"/\[]:;|=,+*?<>'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrCRLF                = @{
			Value  = [string]"`r`n"
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrCR                  = @{
			Value  = [string]"`r"
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrLF                  = @{
			Value  = [string]"`n"
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrTab                 = @{
			Value  = [string]"`t"
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrDollar              = @{
			Value  = [string]'$'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrNoteProperty        = @{
			Value  = [string]'NoteProperty'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrPSObject            = @{
			Value  = [string]'PSObject'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrUTF8                = @{
			Value  = [string]'UTF8'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrAscii               = @{
			Value  = [string]'ascii'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrColon               = @{
			Value  = [String]':'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrConsole             = @{
			Value  = [String]'Console'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrConsoleStop         = @{
			Value  = [String]'ConsoleStop'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrBackSlash           = @{
			Value  = [String]'\'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrExtEXE              = @{
			Value  = [string]'.exe'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrExtCSV              = @{
			Value  = [string]'.csv'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrExtCMD              = @{
			Value  = [string]'.cmd'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrExtTMP              = @{
			Value  = [string]'.tmp'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrExtTEMP             = @{
			Value  = [string]'.temp'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrExtHTML             = @{
			Value  = [string]'.html'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrExtLOG              = @{
			Value  = [string]'.log'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrExtCONF             = @{
			Value  = [string]'.conf'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrExtPDF              = @{
			Value  = [string]'.pdf'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrExtPS1              = @{
			Value  = [string]'.ps1'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrExtPSM1             = @{
			Value  = [string]'.psm1'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrExtPSD1             = @{
			Value  = [string]'.psd1'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrExtPS1XML           = @{
			Value  = [string]'.ps1xml'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrExtTXT              = @{
			Value  = [string]'.txt'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrExtXML              = @{
			Value  = [string]'.xml'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrExtZIP              = @{
			Value  = [string]'.Zip'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		DayOfWeek              = @{
			Value  = [Ordered]@{
				Monday    = 1
				Tuesday   = 2
				Wednesday = 3
				Thursday  = 4
				Friday    = 5
				Saturday  = 6
				Sunday    = 7
				1         = 'Monday'
				2         = 'Tuesday'
				3         = 'Wednesday'
				4         = 'Thursday'
				5         = 'Friday'
				6         = 'Saturday'
				7         = 'Sunday'
			}
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		MonthOfYear            = @{
			Value  = [Ordered]@{
				January   = 1
				February  = 2
				March     = 3
				April     = 4
				May       = 5
				June      = 6
				July      = 7
				August    = 8
				September = 9
				October   = 10
				November  = 11
				December  = 12
				1         = 'January'
				2         = 'February'
				3         = 'March'
				4         = 'April'
				5         = 'May'
				6         = 'June'
				7         = 'July'
				8         = 'August'
				9         = 'September'
				10        = 'October'
				11        = 'November'
				12        = 'December'
			}
			Scope  = $VSScript
			Option = $VOReadOnly
		}
	}
}
Publish-Variables
$MyVars = @{
	N03OtherVars = @{
		LogFilePath            = @{
			Value  = [String]$Null
			Scope  = $VSScript
			Option = $VONone
		}
		LogLevel               = @{
			Value  = [Int]0
			Scope  = $VSScript
			Option = $VONone
		}
		LogLevelSave           = @{
			Value  = [Int]0
			Scope  = $VSScript
			Option = $VONone
		}
		MaxLogLevel            = @{
			Value  = [int]5
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		LogLinePad             = @{
			Value  = [Int]5
			Scope  = $VSScript
			Option = $VONone
		}
		KeepCopies             = @{
			Value  = [int]5
			Scope  = $VSScript
			Option = $VONone
		}
		FileSize               = @{
			Value  = [int]100KB
			Scope  = $VSScript
			Option = $VONone
		}
		FileNumber             = @{
			Value  = [int]10
			Scope  = $VSScript
			Option = $VONone
		}
		FileDays               = @{
			Value  = [int]10
			Scope  = $VSScript
			Option = $VONone
		}
		Console                = @{
			Value  = $False
			Scope  = $VSScript
			Option = $VONone
		}
		EnCoding               = @{
			Value  = 'UTF8'
			Scope  = $VSScript
			Option = $VONone
		}
		WindowHeight           = @{
			Value  = [int]0
			Scope  = $VSScript
			Option = $VONone
		}
		WindowWidth            = @{
			Value  = [int]0
			Scope  = $VSScript
			Option = $VONone
		}
		IsConsole              = @{
			Value  = $False
			Scope  = $VSScript
			Option = $VONone
		}
		MyInitialCallStack     = @{
			Value  = $Null
			Scope  = $VSScript
			Option = $VONone
		}
		MyInitialCallingScript = @{
			Value  = $Null
			Scope  = $VSScript
			Option = $VONone
		}
		FTraceInternalCall     = @{
			Value  = $False
			Scope  = $VSScript
			Option = $VONone
		}
		FTraceAllCalls         = @{
			Value  = $False
			Scope  = $VSScript
			Option = $VONone
		}
		FTLogFilPath           = @{
			Value  = $Null
			Scope  = $VSScript
			Option = $VONone
		}
		FTrace                 = @{
			Value  = $False
			Scope  = $VSScript
			Option = $VONone
		}
		StrContinue            = @{
			Value  = 'Continue'
			Scope  = $VSScript
			Option = $VONone
		}
		StrSilentlyContinue    = @{
			Value  = 'SilentlyContinue'
			Scope  = $VSScript
			Option = $VONone
		}
		StrInquire             = @{
			Value  = 'Inquire'
			Scope  = $VSScript
			Option = $VONone
		}
		StrStop                = @{
			Value  = 'Stop'
			Scope  = $VSScript
			Option = $VONone
		}
		StrVerbose             = @{
			Value  = 'Verbose'
			Scope  = $VSScript
			Option = $VONone
		}

			}
}
Publish-Variables
$MyVars = @{
	N09Finalise = @{
		DefineVariables = @{
			Value  = $True
			Scope  = $VSScript
			Option = $VOReadOnly
			Use    = 'Common'
		}
#		RootServersAddresses = @{
#    Value  = ( (. (Join-Path $ModuleScriptRoot 'Helpers\Get-RootHints.ps1')).RootServerAddresses )
#    Scope  = $VSScript
#    Option = $VONone
#}
	}
}
Publish-Variables
