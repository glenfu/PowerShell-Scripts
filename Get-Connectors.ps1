# Author: Glen Fu
# Date: 24/12/2021
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

#Get-Connectors.ps1
#How to run script: .\Get-Connectors.ps1 -AdminUsername <admin username> -AdminPassword <password>
Param(
    [string] [Parameter(Mandatory = $true)]  $AdminUsername,
    [string] [Parameter(Mandatory = $true)]  $AdminPassword
)

# Required Modules (installed as admin)
Write-Host "Check and install missing PowerShell Modules..." -ForegroundColor Green
(Get-Module -Name 'Microsoft.PowerApps.Administration.PowerShell' -ListAvailable) -or (Install-Module -Name Microsoft.PowerApps.Administration.PowerShell -Scope AllUsers -Repository PSGallery -Force -AllowClobber) | Out-Null
(Get-Module -Name 'Microsoft.PowerApps.PowerShell' -ListAvailable) -or (Install-Module -Name Microsoft.PowerApps.PowerShell -Scope AllUsers -Repository PSGallery -Force -AllowClobber) | Out-Null

$adminPW = ConvertTo-SecureString $AdminPassword -AsPlainText -Force

Write-Host "Sign in Power Apps account as $AdminUsername" -ForegroundColor Green

Try
{
    $connected = Add-PowerAppsAccount -Username $AdminUsername -Password $adminPW
}
Catch
{
     throw
}

# Get list of all environments
$environments = Get-PowerAppEnvironment | Select-Object -Property EnvironmentName, DisplayName 
$connectorsList = @()

# Loop through all environments 
foreach ($environment in $environments)
{
    # List all apps in each environment
    $appNames = Get-PowerApp -EnvironmentName $environment.EnvironmentName | Select-Object -Property AppName, DisplayName, CreatedTime

    # Loop through each app to get connectors it is using
    foreach ($appName in $appNames) {
        $connectors = Get-AdminPowerAppConnectionReferences -EnvironmentName $environment.EnvironmentName -AppName $appName.AppName

        # Write outputs
        Write-Host "Get connectors used by"$appName.DisplayName -ForegroundColor Green
        ForEach ($connector in $connectors) {
            $connectorDetails = New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $environment.DisplayName `
            | Add-Member -PassThru -MemberType NoteProperty -Name ApplicationName -Value $appName.DisplayName `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value $connector.ConnectorName `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorDisplayName -Value $connector.displayName `
            | Add-Member -PassThru -MemberType NoteProperty -Name UPN -Value $connector.CreatedBy.userPrincipalName `
            | Add-Member -PassThru -MemberType NoteProperty -Name CreatedTime -Value $appName.CreatedTime `

            $connectorsList += $connectorDetails
        }
    }

    #Connectors in environment that user is part ofn
    $connections = Get-AdminPowerAppConnection -EnvironmentName $environment.EnvironmentName
    $environmentName = Get-AdminPowerAppEnvironment -EnvironmentName $environment.EnvironmentName | Select-Object -Property DisplayName
    Write-Host "Get user's connectors for environment:"$environmentName.DisplayName -ForegroundColor Gree
    foreach ($connection in $connections) {
        $connectionDetails = New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $environmentName.DisplayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name ApplicationName -Value $null `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value $connection.ConnectorName `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorDisplayName -Value $connection.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name UPN -Value $connection.CreatedBy.userPrincipalName `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedTime -Value $connection.CreatedTime `
        
        $connectorsList += $connectionDetails
    }
}
$currentDate = Get-Date -Format 'dd-MM-yyyy hhmm'
$csvPath = ".\connectors "+$currentDate+".csv" 
$connectorsList | Format-Table -AutoSize
$connectorsList | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Completed export to csv file:"$csvPath -ForegroundColor Green