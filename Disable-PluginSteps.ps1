# Author: Glen Fu
# Date: 04/05/2022
# Version: 1.0
# Copyright © Microsoft Corporation.  All Rights Reserved.
# This code released under the terms of the 
# Microsoft Public License (MS-PL, http://opensource.org/licenses/ms-pl.html.)
# Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment. 
# THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
# INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. 
# We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that. 
# You agree: 
# (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; 
# (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; 
# and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys’ fees, that arise or result from the use or distribution of the Sample Code 

#Disable-PluginSteps.ps1
#How to run script: .\Disable-PluginSteps.ps1 -ServerURL <Server URL> -ApplicationID <Application ID> -ClientSecret <client secret> -PluginName <plugin name / prefix> -Enabled <true to enable plugin steps, false to disable plugin steps)

Param(
    [string] [Parameter(Mandatory = $true)]  $ServerURL,
    [string] [Parameter(Mandatory = $true)]  $ApplicationID,
    [string] [Parameter(Mandatory = $true)]  $ClientSecret,
    [string] [Parameter(Mandatory = $true)]  $PluginName,
    [string] [Parameter(Mandatory = $true)]  $Enabled
)

function EnablePluginStep {
    param
    (
        [Guid] $StepId    
    )

    Set-CrmRecordState -EntityLogicalName sdkmessageprocessingstep -Id $StepId `
        -StateCode Enabled -StatusCode Enabled
}

function DisablePluginStep {
    param
    (
        [Guid] $StepId    
    )

    Set-CrmRecordState -EntityLogicalName sdkmessageprocessingstep -Id $StepId `
        -StateCode Disabled -StatusCode Disabled
}

Try {
    Connect-CrmOnline -ServerUrl $ServerURL -ClientSecret $ClientSecret -OAuthClientId $ApplicationID                
}
Catch {
    throw
}

# First of all, filter all custom assemblies by plugin name prefix
$assemblies = Get-CrmRecords -conn $conn -EntityLogicalName pluginassembly `
    -FilterAttribute name -FilterOperator like -FilterValue $PluginName `
    -Fields * -WarningAction SilentlyContinue

# Display retrieved assemblies name
$assemblies.CrmRecords | select name

# Instantiate a List to contain Steps
$steps = New-Object System.Collections.Generic.List[object]

# Loop all assemblies to get steps. 
foreach ($assembly in $assemblies.CrmRecords) {
    Write-Host 'Getting Steps for' $assembly.name

    # Get all registered steps for the assembly
    $sdkmessages = Get-CrmSdkMessageProcessingStepsForPluginAssembly `
        -conn $conn -PluginAssemblyName $assembly.name -WarningAction SilentlyContinue
    
    if ($Enabled -ne $true) {
        # Add only enabled step to the list
        foreach ($enabledStep in ($sdkmessages | ? { $_.statecode -eq 'Enabled' })) {
            $steps.Add($enabledStep)
        }
    }
    else {
        # Add only disabled step to the list
        foreach ($enabledStep in ($sdkmessages | ? { $_.statecode -eq 'Disabled' })) {
            $steps.Add($enabledStep)
        }
    }
}

if ($Enabled -ne $true) {
    # Disable all enabled steps.
    foreach ($step in $steps) {
        Write-Host 'Disabled' $step.name
        DisablePluginStep -StepId $step.sdkmessageprocessingstepid
    }
}
else {
    # Enable all disabled steps.
    foreach ($step in $steps) {
        Write-Host 'Enabled' $step.name
        EnablePluginStep -StepId $step.sdkmessageprocessingstepid
    }
}