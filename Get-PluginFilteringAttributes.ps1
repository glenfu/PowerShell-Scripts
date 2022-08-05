# Author: Glen Fu
# Date: 05/08/2022
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

#Get-PluginFilteringAttributes.ps1
#How to run script: .\Get-PluginFilteringAttributes.ps1 -ServerURL <Server URL> -ApplicationID <Application ID> -ClientSecret <client secret>

Param(
    [string] [Parameter(Mandatory = $true)]  $ServerURL,
    [string] [Parameter(Mandatory = $true)]  $ApplicationID,
    [string] [Parameter(Mandatory = $true)]  $ClientSecret
)

Try {
    Connect-CrmOnline -ServerUrl $ServerURL -ClientSecret $ClientSecret -OAuthClientId $ApplicationID                
}
Catch {
    throw
}

# First of all, get all custom assemblies by plugin name
$assemblies = Get-CrmRecords -conn $conn -EntityLogicalName pluginassembly -Fields * -WarningAction SilentlyContinue

# Loop all assemblies to get steps. 
foreach ($assembly in $assemblies.CrmRecords) {
    Write-Host 'Getting Steps for' $assembly.name

    # Get all registered steps for the assembly
    $sdkmessages = Get-CrmSdkMessageProcessingStepsForPluginAssembly `
        -conn $conn -PluginAssemblyName $assembly.name -WarningAction SilentlyContinue

    foreach ($step in $sdkmessages) {
        if (![string]::IsNullOrEmpty($step.filteringattributes_Property)) { 
            Write-Host $step.filteringattributes_Property
        }
    }
}