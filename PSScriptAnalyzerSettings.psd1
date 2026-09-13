# PSScriptAnalyzer settings for this module. PSScriptAnalyzer auto-discovers this file when scanning
# from (or below) this folder, so a plain `Invoke-ScriptAnalyzer -Recurse` run against a fresh clone
# picks these up automatically - unlike this repo's internal accepted-findings baseline
# (Tools\RepoLint-Baseline.psd1), which lives in the private master repo and never ships here.
#
# Two kinds of exclusion below, for two different reasons - see each comment.
@{
	ExcludeRules = @(
		# --- Parser noise, not real findings -------------------------------------------------
		# PSScriptAnalyzer parses each file in isolation, so a type introduced by a `using
		# namespace`/`using module` statement elsewhere is not visible yet at parse time - this
		# module's Classes\ tree uses `using namespace` heavily (DnsBinaryReader/Writer etc.),
		# which fires the rule below on every reference, even though the code is correct and
		# works at runtime. Confirmed repo-wide (see this repo's own Tools\Test-RepoLint.ps1,
		# which filters the identical set for the same reason).
		'TypeNotFound',
		'MemberAlreadyDefined',
		'AmbiguousTypeReference',

		# --- Deliberate style choice, not accepted debt --------------------------------------
		# Write-Host is used throughout this module's console-facing diagnostic/trace output by
		# design (colored status text a human is meant to read directly) - not an oversight.
		'PSAvoidUsingWriteHost'
	)
}
