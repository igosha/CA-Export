###############################################################################
# Conditional Access Export Utility - OFFLINE from JSON file
# Reads policies from a manually exported JSON file from:
#   https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies
#
# Based on Export-CaPolicy.ps1 by Douglas Baker / Andres Bohren
# Adapted to work offline from a JSON file export.
###############################################################################

<#
.SYNOPSIS
	Exports Conditional Access Policies from a JSON file to HTML format.

.DESCRIPTION
	Reads CA policies from a JSON file that was manually exported from the
	Microsoft Graph API endpoint:
	  https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies

	Produces an HTML report structured like the Entra Portal.

	GUID resolution for users, groups, apps, roles, and named locations is
	OPTIONAL and requires a live Microsoft Graph connection. Without it, the
	report will show raw GUIDs.

.PARAMETER FilePath
	Path to the JSON file containing the Graph API response.
	The file must contain either:
	  - The full Graph response with a "value" array, or
	  - A plain JSON array of policy objects.

.PARAMETER PolicyID
	Optional. Export only the policy with this ID.

.PARAMETER ResolveGuids
	Switch. When specified the script connects to Microsoft Graph and
	resolves user/group/app/role/location GUIDs to display names.
	Requires the Microsoft.Graph PowerShell module.

.PARAMETER TenantName
	Optional tenant display name for the report header.
	Defaults to "Offline Export".

.EXAMPLE
	.\Export-CaPolicyFromFile.ps1 -FilePath .\policies.json
	# Produces HTML with raw GUIDs (fully offline)

.EXAMPLE
	.\Export-CaPolicyFromFile.ps1 -FilePath .\policies.json -ResolveGuids
	# Produces HTML with resolved display names (requires Graph connection)

.EXAMPLE
	.\Export-CaPolicyFromFile.ps1 -FilePath .\policies.json -PolicyID "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	# Export a single policy
#>
[CmdletBinding()]
param (
	[Parameter(Mandatory = $true)]
	[String]
	$FilePath,

	[Parameter()]
	[String]
	$PolicyID,

	[Parameter()]
	[Switch]
	$ResolveGuids,

	[Parameter()]
	[String]
	$TenantName = "Offline Export"
)

#ExportLocation
$ExportLocation = $PSScriptRoot
$FileName = "\CAPolicy.html"
$HTMLExport = $true

###############################################################################
# Read and parse the JSON file
###############################################################################
if (-not (Test-Path $FilePath)) {
	Write-Error "File not found: $FilePath"
	return
}

Write-Host "Reading: $FilePath"
$RawJson = Get-Content -Path $FilePath -Raw -Encoding UTF8
$Parsed = $RawJson | ConvertFrom-Json

# Support both { "value": [...] } envelope and plain array [...]
if ($null -ne $Parsed.value) {
	$CAPolicy = $Parsed.value
} else {
	$CAPolicy = $Parsed
}

Write-Host "Found $($CAPolicy.Count) policies in file"

# Filter by PolicyID if specified
if ($PolicyID) {
	$CAPolicy = $CAPolicy | Where-Object { $_.id -eq $PolicyID }
	if ($null -eq $CAPolicy -or @($CAPolicy).Count -eq 0) {
		Write-Error "Policy with ID '$PolicyID' not found in file."
		return
	}
	Write-Host "Filtered to policy: $($CAPolicy.displayName)"
}

###############################################################################
# Helper: safely read a property from the Graph JSON (camelCase, nested)
###############################################################################
function Get-JsonProp {
	param($Obj, [string[]]$Path)
	$current = $Obj
	foreach ($p in $Path) {
		if ($null -eq $current) { return $null }
		$current = $current.$p
	}
	return $current
}

###############################################################################
# Extract values from the raw Graph API JSON (camelCase properties)
###############################################################################
$date = Get-Date

$CAExport = [PSCustomObject]@()

$AdUsers = @()
$Apps = @()

Write-Host "Extracting: CA Policy Data"
foreach ($Policy in $CAPolicy) {
	### Conditions ###
	$IncludeUG = @()
	$val = Get-JsonProp $Policy 'conditions','users','includeUsers'
	if ($val) { $IncludeUG += $val }
	$val = Get-JsonProp $Policy 'conditions','users','includeGroups'
	if ($val) { $IncludeUG += $val }
	$val = Get-JsonProp $Policy 'conditions','users','includeRoles'
	if ($val) { $IncludeUG += $val }

	$ExcludeUG = @()
	$val = Get-JsonProp $Policy 'conditions','users','excludeUsers'
	if ($val) { $ExcludeUG += $val }
	$val = Get-JsonProp $Policy 'conditions','users','excludeGroups'
	if ($val) { $ExcludeUG += $val }
	$val = Get-JsonProp $Policy 'conditions','users','excludeRoles'
	if ($val) { $ExcludeUG += $val }

	$inclApps = Get-JsonProp $Policy 'conditions','applications','includeApplications'
	$exclApps = Get-JsonProp $Policy 'conditions','applications','excludeApplications'
	if ($inclApps) { $Apps += $inclApps }
	if ($exclApps) { $Apps += $exclApps }

	$AdUsers += $ExcludeUG
	$AdUsers += $IncludeUG

	$InclLocation = Get-JsonProp $Policy 'conditions','locations','includeLocations'
	$ExclLocation = Get-JsonProp $Policy 'conditions','locations','excludeLocations'

	$InclPlat = Get-JsonProp $Policy 'conditions','platforms','includePlatforms'
	$ExclPlat = Get-JsonProp $Policy 'conditions','platforms','excludePlatforms'

	$InclDev = Get-JsonProp $Policy 'conditions','devices','includeDevices'
	$ExclDev = Get-JsonProp $Policy 'conditions','devices','excludeDevices'
	$devFilterRule = Get-JsonProp $Policy 'conditions','devices','deviceFilter','rule'

	$userActions = Get-JsonProp $Policy 'conditions','applications','includeUserActions'
	$authContext = Get-JsonProp $Policy 'conditions','applications','includeAuthenticationContextClassReferences'

	$userRiskLevels = Get-JsonProp $Policy 'conditions','userRiskLevels'
	$signInRiskLevels = Get-JsonProp $Policy 'conditions','signInRiskLevels'
	$clientAppTypes = Get-JsonProp $Policy 'conditions','clientAppTypes'

	### Grant Controls ###
	$builtInControls = Get-JsonProp $Policy 'grantControls','builtInControls'
	$termsOfUse      = Get-JsonProp $Policy 'grantControls','termsOfUse'
	$customAuth      = Get-JsonProp $Policy 'grantControls','customAuthenticationFactors'
	$grantOperator   = Get-JsonProp $Policy 'grantControls','operator'

	### Session Controls ###
	$sessionControls = $Policy.sessionControls

	$CAExport += New-Object PSObject -Property @{
		### Users ###
		Users = ""
		Name = $Policy.displayName
		PolicyID = $Policy.id
		Status = $Policy.state
		UsersInclude = (($IncludeUG | Where-Object { $_ }) -join ", `r`n")
		UsersExclude = (($ExcludeUG | Where-Object { $_ }) -join ", `r`n")

		### Cloud apps or actions ###
		'TargetResources' = ""
		ApplicationsIncluded = (($inclApps | Where-Object { $_ }) -join ", `r`n")
		ApplicationsExcluded = (($exclApps | Where-Object { $_ }) -join ", `r`n")
		userActions = (($userActions | Where-Object { $_ }) -join ", `r`n")
		AuthContext = (($authContext | Where-Object { $_ }) -join ", `r`n")

		### Network ###
		'Network' = ""
		LocationsIncluded = (($InclLocation | Where-Object { $_ }) -join ", `r`n")
		LocationsExcluded = (($ExclLocation | Where-Object { $_ }) -join ", `r`n")

		### Conditions ###
		Conditions = ""
		UserRisk = (($userRiskLevels | Where-Object { $_ }) -join ", `r`n")
		SignInRisk = (($signInRiskLevels | Where-Object { $_ }) -join ", `r`n")
		PlatformsInclude = (($InclPlat | Where-Object { $_ }) -join ", `r`n")
		PlatformsExclude = (($ExclPlat | Where-Object { $_ }) -join ", `r`n")
		ClientApps = (($clientAppTypes | Where-Object { $_ }) -join ", `r`n")
		DevicesIncluded = (($InclDev | Where-Object { $_ }) -join ", `r`n")
		DevicesExcluded = (($ExclDev | Where-Object { $_ }) -join ", `r`n")
		DeviceFilters = if ($devFilterRule) { $devFilterRule } else { "" }

		### Grant Controls ###
		GrantControls = ""
		BuiltInControls = $(($builtInControls | Where-Object { $_ }) -join " ")
		TermsOfUse = $($termsOfUse -join " ")
		CustomControls = $($customAuth -join " ")
		GrantOperator = if ($grantOperator) { $grantOperator } else { "" }

		### Session Controls ###
		SessionControls = ""
		SessionControlsAdditionalProperties = ""
		ApplicationEnforcedRestrictionsIsEnabled = Get-JsonProp $sessionControls 'applicationEnforcedRestrictions','isEnabled'
		ApplicationEnforcedRestrictionsAdditionalProperties = ""
		CloudAppSecurityType = Get-JsonProp $sessionControls 'cloudAppSecurity','cloudAppSecurityType'
		CloudAppSecurityIsEnabled = Get-JsonProp $sessionControls 'cloudAppSecurity','isEnabled'
		CloudAppSecurityAdditionalProperties = ""
		DisableResilienceDefaults = Get-JsonProp $sessionControls 'disableResilienceDefaults'
		PersistentBrowserIsEnabled = Get-JsonProp $sessionControls 'persistentBrowser','isEnabled'
		PersistentBrowserMode = Get-JsonProp $sessionControls 'persistentBrowser','mode'
		PersistentBrowserAdditionalProperties = ""
		SignInFrequencyAuthenticationType = Get-JsonProp $sessionControls 'signInFrequency','authenticationType'
		SignInFrequencyInterval = Get-JsonProp $sessionControls 'signInFrequency','frequencyInterval'
		SignInFrequencyIsEnabled = Get-JsonProp $sessionControls 'signInFrequency','isEnabled'
		SignInFrequencyType = Get-JsonProp $sessionControls 'signInFrequency','type'
		SignInFrequencyValue = Get-JsonProp $sessionControls 'signInFrequency','value'
		SignInFrequencyAdditionalProperties = ""
	}
}

###############################################################################
# OPTIONAL: Resolve GUIDs to display names (requires Graph connection)
###############################################################################
if ($ResolveGuids) {
	Write-Host ""
	Write-Host "ResolveGuids requested - connecting to Microsoft Graph..."

	# Test Graph Module
	$GraphModule = Get-Module "Microsoft.Graph" -ListAvailable
	if ($null -eq $GraphModule) {
		Write-Host "Microsoft.Graph Module not installed - skipping GUID resolution" -ForegroundColor Yellow
		Write-Host "Use: Install-Module -Name Microsoft.Graph" -ForegroundColor Yellow
	} else {
		# Connect
		$MgContext = Get-MgContext
		if ($null -eq $MgContext) {
			Write-Host "Connect-MgGraph"
			Connect-MgGraph -Scopes 'Policy.Read.All', 'Directory.Read.All', 'Application.Read.All' -NoWelcome
		}

		Write-Host "Converting: Entra ID GUIDs"
		$cajson = $CAExport | ConvertTo-Json -Depth 4

		# Resolve user / group / role object IDs
		$ADsearch = $AdUsers | Where-Object { $_ -ne 'All' -and $_ -ne 'GuestsOrExternalUsers' -and $_ -ne 'None' -and $_ -match '^[0-9a-fA-F\-]{36}$' }
		$ADsearch = $ADsearch | Select-Object -Unique
		if ($ADsearch.Count -gt 0) {
			Get-MgDirectoryObjectById -Ids $ADsearch | ForEach-Object {
				$obj = $_.Id
				$disp = $_.AdditionalProperties.displayName
				if ($disp) { $cajson = $cajson -replace [regex]::Escape($obj), $disp }
			}
		}
		$CAExport = $cajson | ConvertFrom-Json

		# Resolve Application IDs
		$AppSearch = $Apps | Where-Object { $_ -ne 'All' -and $_ -ne 'None' -and $_ -ne 'Office365' -and $_ -ne 'MicrosoftAdminPortals' -and $_ -match '^[0-9a-fA-F\-]{36}$' }
		$AppSearch = $AppSearch | Select-Object -Unique
		if ($AppSearch.Count -gt 0) {
			$allApps = Get-MgServicePrincipal -All
			$allApps | Where-Object { $_.AppId -in $AppSearch } | ForEach-Object {
				$obj = $_.AppId
				$disp = $_.DisplayName
				if ($disp) { $cajson = $cajson -replace [regex]::Escape($obj), $disp }
			}
		}

		# Resolve Named Location IDs
		Get-MgIdentityConditionalAccessNamedLocation | ForEach-Object {
			$obj = $_.Id
			$disp = $_.DisplayName
			if ($disp) { $cajson = $cajson -replace [regex]::Escape($obj), $disp }
		}

		# Resolve Role Template IDs
		Get-MgDirectoryRoleTemplate | ForEach-Object {
			$obj = $_.Id
			$disp = $_.DisplayName
			if ($disp) { $cajson = $cajson -replace [regex]::Escape($obj), $disp }
		}

		$CAExport = $cajson | ConvertFrom-Json
	}
} else {
	Write-Host ""
	Write-Host "Tip: Use -ResolveGuids to resolve GUIDs to display names (requires Graph connection)" -ForegroundColor Cyan
}

###############################################################################
# Pivot for HTML output (identical to original)
###############################################################################
Write-Host "Pivoting: CA to Export Format"
$pivot = @()
$rowItem = New-Object PSObject
$rowitem | Add-Member -type NoteProperty -Name 'CA Item' -Value "row1"
$Pcount = 1
foreach ($CA in $CAExport) {
	$rowitem | Add-Member -type NoteProperty -Name "Policy $pcount" -Value "row1"
	$pcount += 1
}
$pivot += $rowItem

# Add Data to Report
$Rows = $CAExport | Get-Member | Where-Object { $_.MemberType -eq "NoteProperty" }
$Rows | ForEach-Object {
	$rowItem = New-Object PSObject
	$rowname = $_.Name
	$rowitem | Add-Member -type NoteProperty -Name 'CA Item' -Value $_.Name
	$Pcount = 1
	foreach ($CA in $CAExport) {
		$ca | Get-Member | Where-Object { $_.MemberType -eq "NoteProperty" } | ForEach-Object {
			$a = $_.name
			$b = $ca.$a
			if ($a -eq $rowname) {
				$rowitem | Add-Member -type NoteProperty -Name "Policy $pcount" -Value $b
			}
		}
		$pcount += 1
	}
	$pivot += $rowItem
}

###############################################################################
# Column Sorting Order
###############################################################################
$sort = "Name","PolicyID","Status","Users","UsersInclude","UsersExclude","TargetResources","ApplicationsIncluded","ApplicationsExcluded",`
		"userActions","AuthContext","Network","LocationsIncluded","LocationsExcluded", "Conditions","UserRisk","SignInRisk","PlatformsInclude",`
		"PlatformsExclude","ClientApps","Devices","DevicesIncluded","DevicesExcluded","DeviceFilters",`
		"GrantControls", "BuiltInControls", "TermsOfUse", "CustomControls", "GrantOperator",`
		"SessionControls","SessionControlsAdditionalProperties","ApplicationEnforcedRestrictionsIsEnabled","ApplicationEnforcedRestrictionsAdditionalProperties",`
		"CloudAppSecurityType","CloudAppSecurityIsEnabled","CloudAppSecurityAdditionalProperties","DisableResilienceDefaults","PersistentBrowserIsEnabled",`
		"PersistentBrowserMode","PersistentBrowserAdditionalProperties","SignInFrequencyAuthenticationType","SignInFrequencyInterval","SignInFrequencyIsEnabled",`
		"SignInFrequencyType","SignInFrequencyValue","SignInFrequencyAdditionalProperties"

###############################################################################
# HTML Export
###############################################################################
if ($HTMLExport) {
	Write-Host "Saving to File: HTML"
	$jquery = '<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
	<script>
	$(document).ready(function(){
		$("tr").click(function(){
		if(!$(this).hasClass("selected")){
			$(this).addClass("selected");
		} else {
			$(this).removeClass("selected");
		}

		});
		$("th").click(function(){
		if(!$(this).hasClass("colselected")){
			$(this).addClass("colselected");
		} else {
			$(this).removeClass("colselected");
		}

		});
	});
	</script>'
$html = "<html><head><base href='https://docs.microsoft.com/' target='_blank'>
	$jquery<style>
	.title{
		display: block;
		font-size: 2em;
		margin-block-start: 0.67em;
		margin-block-end: 0.67em;
		margin-inline-start: 0px;
		margin-inline-end: 0px;
		font-weight: bold;
		font-family: Segoe UI;
	}
	table{
		border-collapse: collapse;
		margin: 25px 0;
		font-size: 0.9em;
		font-family: Segoe UI;
		min-width: 400px;
		box-shadow: 0 0 20px rgba(0, 0, 0, 0.15) ;
		text-align: center;
	}
	thead tr {
		background-color: #009879;
		color: #ffffff;
		text-align: left;
	}
	th, td {
		min-width: 250px;
		padding: 12px 15px;
		border: 1px solid lightgray;
		vertical-align: top;
	}
	td {
		vertical-align: top;
	}
	tbody tr {
		border-bottom: 1px solid #dddddd;
	}
	tbody tr:nth-of-type(even) {
		background-color: #f3f3f3;
	}
	tbody tr:nth-of-type(5), tbody tr:nth-of-type(8), body tr:nth-of-type(13),tbody tr:nth-of-type(16), tbody tr:nth-of-type(25), tbody tr:nth-of-type(30){
		background-color: #36c;
		text-aling:left !important
	}
	tbody tr:last-of-type {
		border-bottom: 2px solid #009879;
	}
	tr:hover{
	background-color: #ffea76!important;
	}
	.selected:not(th){
		background-color:#ffea76!important;
	}
	th{
		background-color:white !important;
	}
	.colselected {
	background-color: rgb(93, 236, 213)!important;
	}
	table tr th:first-child,table tr td:first-child {
		position: sticky;
		inset-inline-start: 0; 
		background-color: #36c!important;
		Color: #fff;
		font-weight: bolder;
		text-align: center;
	}
	</style></head><body> <div class='Title'>CA Export: $TenantName - $Date </div>"

	Write-Host "Launching: Web Browser"
	$Launch = $ExportLocation + $FileName
	$HTML += $pivot | Where-Object { $_."CA Item" -ne 'row1' } | Sort-Object { $sort.IndexOf($_."CA Item") } | ConvertTo-Html -Fragment
	$HTML | Out-File $Launch
	Start-Process $Launch
}