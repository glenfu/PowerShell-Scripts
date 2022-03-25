# Author: Glen Fu
# Date: 30/12/2021
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

#Get-DLP.ps1
#How to run script: .\Get-DLP.ps1 -AdminUsername <admin username> -AdminPassword <password>
Param(
    [string] [Parameter(Mandatory = $true)]  $AdminUsername,
    [string] [Parameter(Mandatory = $true)]  $AdminPassword
)

Function Get-Connector
{
    param
    (   
        [PSObject]$DLPPolicy
    )

    $dlplist = @()
    $environmentName = ''

    $businessCategoryConnectors = $DLPPolicy | Select-Object -ExpandProperty BusinessDataGroup
    if ($environment -ne $null)
    {
        $environmentName = Get-AdminPowerAppEnvironment -EnvironmentName $environment.name
    }
    
    foreach($connector in $businessCategoryConnectors)  
    {  
        $dlp = New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentIntID  -Value $environment.id `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentType -Value $environment.type `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentID -Value $environment.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $environmentName.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name PolicyID -Value $DLPPolicy.PolicyName `
        | Add-Member -PassThru -MemberType NoteProperty -Name PolicyName -Value $DLPPolicy.DisplayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name GroupName -Value 'BusinessDataGroup' `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorID -Value $connector.id `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value $connector.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorType -Value $connector.type
        
        $dlplist += $dlp
    }

    $nonBusinessCategoryConnectors = $DLPPolicy | Select-Object -ExpandProperty NonBusinessDataGroup  
    foreach($connector in $nonBusinessCategoryConnectors)  
    {  
        $dlp = New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentIntID  -Value $environment.id `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentType -Value $environment.type `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentID -Value $environment.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $environmentName.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name PolicyID -Value $DLPPolicy.PolicyName `
        | Add-Member -PassThru -MemberType NoteProperty -Name PolicyName -Value $DLPPolicy.DisplayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name GroupName -Value 'NonBusinessDataGroup' `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorID -Value $connector.id `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value $connector.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorType -Value $connector.type
        
        $dlplist += $dlp
    }

    $blockedCategoryConnectors = $DLPPolicy | Select-Object -ExpandProperty BlockedGroup  
    foreach($connector in $blockedCategoryConnectors)  
    {  
        $dlp = New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentIntID -Value $environment.id `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentType -Value $environment.type `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentID -Value $environment.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $environmentName.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name PolicyID -Value $DLPPolicy.PolicyName `
        | Add-Member -PassThru -MemberType NoteProperty -Name PolicyName -Value $DLPPolicy.DisplayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name GroupName -Value 'BlockedGroup' `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorID -Value $connector.id `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value $connector.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorType -Value $connector.type
        
        $dlplist += $dlp
    }

    return $dlplist
}

$dlpList = @()

# Required Modules (installed as admin)
Write-Host "Check and install missing PowerShell Modules..." -ForegroundColor Green
(Get-Module -Name 'Microsoft.PowerApps.Administration.PowerShell' -ListAvailable) -or (Install-Module -Name Microsoft.PowerApps.Administration.PowerShell -Scope AllUsers -Repository PSGallery -Force -AllowClobber) | Out-Null

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

$dlpPolicies = Get-AdminDlpPolicy
foreach ($dlpPolicy in $dlpPolicies) 
{
    $environments = $dlpPolicy | Select-Object -ExpandProperty Environments 
    
    if ($environments.Count -ne 0)
    {
        foreach ($environment in $environments) 
        {
            $dlpList += Get-Connector -DLPPolicy $dlpPolicy
        }
    }
    else 
    {
        $environment = $null
        $dlpList += Get-Connector -DLPPolicy $dlpPolicy
    }
} 

$currentDate = Get-Date -Format 'dd-MM-yyyy hhmm'
$csvPath = ".\dlp "+$currentDate+".csv" 
$dlpList | Format-Table -AutoSize
$dlpList | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Completed export to csv file:"$csvPath -ForegroundColor Green