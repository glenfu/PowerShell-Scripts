# Author: Glen Fu
# Date: 24/11/2022
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

#Get-DailyCapacity.ps1
#How to run script: .\Get-DailyCapacity.ps1
# Param(
#     [string] [Parameter(Mandatory = $true)]  $AdminUsername,
#     [string] [Parameter(Mandatory = $true)]  $AdminPassword
# )

# Required Modules (installed as admin)
(Get-Module -Name 'AzureAD' -ListAvailable) -or (Install-Module -Name AzureAD -Scope AllUsers -Repository PSGallery -Force -AllowClobber) | Out-Null
Write-Host "Check and install missing PowerShell Modules..." -ForegroundColor Green
(Get-Module -Name 'Microsoft.PowerApps.Administration.PowerShell' -ListAvailable) -or (Install-Module -Name Microsoft.PowerApps.Administration.PowerShell -Scope AllUsers -Repository PSGallery -Force -AllowClobber) | Out-Null

Write-Host "Creating a session against the Power Platform API" -ForegroundColor Green

# Set variables for your session
$TenantId = ""
$SPNId = ""
$ClientSecret = ""

$capacityDetailsList = @()

Try {
    Add-PowerAppsAccount -Endpoint prod -TenantID $TenantId -ApplicationId $SPNId -ClientSecret $ClientSecret
}
Catch {
    throw
}

#fetch environment list with capacity populated.  This is only possible when calling full environment list
$environmentsList = Get-AdminPowerAppEnvironment -Capacity

foreach ($environment in $environmentsList) {
    Write-Host "Traversing environment " $environment.DisplayName " capacity metadata..."
    #Write-Host $environment
   
    foreach ($capacityObject in $environment.Capacity) {
        $EnvironmentCapacity = New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $environment.DisplayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name Description -Value $environment.Description `
        | Add-Member -PassThru -MemberType NoteProperty -Name Type -Value $environment.EnvironmentType `
        | Add-Member -PassThru -MemberType NoteProperty -Name ActualConsumption -Value $capacityObject.actualConsumption `
        | Add-Member -PassThru -MemberType NoteProperty -Name CapacityType -Value $capacityObject.capacityType `
        | Add-Member -PassThru -MemberType NoteProperty -Name CapacityUnit -Value $capacityObject.capacityUnit `
        | Add-Member -PassThru -MemberType NoteProperty -Name UpdatedOn -Value $capacityObject.updatedOn
        
        $capacityDetailsList += $EnvironmentCapacity
    }
    
    Write-Host "==============================="
    
}

$currentDate = Get-Date -Format 'dd-MM-yyyy hhmm'
$csvPath = ".\capacity " + $currentDate + ".csv" 
$capacityDetailsList | Format-Table -AutoSize
$capacityDetailsList | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Completed export to csv file:"$csvPath -ForegroundColor Green