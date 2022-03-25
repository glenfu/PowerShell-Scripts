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

#Set-DLP.ps1
#How to run script: .\Set-DLP.ps1 -AdminUsername <admin username> -AdminPassword <password>
Param(
    [string] [Parameter(Mandatory = $true)]  $AdminUsername,
    [string] [Parameter(Mandatory = $true)]  $AdminPassword,
    [string] [Parameter(Mandatory = $true)]  $csvPath
)

Function Update-DlpPolicy 
{    
    param
    ( 
        [PSObject]$DlpPolicy
    )

    $policy = Get-DlpPolicy -PolicyName $DlpPolicy.PolicyID

    $generalGroup = $policy.connectorGroups | Where-Object { $_.classification -eq 'General' }
    $connectorInGeneral = $generalGroup.connectors | where { $_.name -eq $DlpPolicy.ConnectorName  }

    $confidentialGroup = $policy.connectorGroups | Where-Object { $_.classification -eq 'Confidential' }
    $connectorInConfidential = $confidentialGroup.connectors | where { $_.name -eq $DlpPolicy.ConnectorName }

    $blockedGroup = $policy.connectorGroups | Where-Object { $_.classification -eq 'Blocked' }
    $connectorInBlocked = $blockedGroup.connectors | where { $_.name -eq $DlpPolicy.ConnectorName }

    if ($connectorInGeneral -ne $null -and $DlpPolicy.GroupName -eq 'BusinessDataGroup') 
    {
        Write-Host "Move connector $($DlpPolicy.ConnectorName) from NonBusinessDataGroup to BusinessDataGroup." -ForegroundColor Green
        
        #Add the connector to the business data group policy
        $confidentialGroup.connectors += $connectorInGeneral

        #remove the connector from non business data group policy
        $generalConnectorExcludingSpecifiedConnector = $generalGroup.connectors | where { $_.id -ne $DlpPolicy.ConnectorID }
        
        $generalGroup.connectors = [Array]$generalConnectorExcludingSpecifiedConnector

        Set-DlpPolicy -PolicyName $policy.name -UpdatedPolicy $policy
        Write-Host $policy.connectorGroups
    }
    elseif ($connectorInGeneral -ne $null -and $DlpPolicy.GroupName -eq 'BlockedGroup') 
    {
        Write-Host "Move connector $($DlpPolicy.ConnectorName) from NonBusinessDataGroup to BlockedGroup." -ForegroundColor Green

        #Add the connector to the blocked data group policy
        $blockedGroup.connectors += $connectorInGeneral

        #remove the connector from non business data group policy
        $generalConnectorExcludingSpecifiedConnector = $generalGroup.connectors | where { $_.id -ne $DlpPolicy.ConnectorID }
        
        $generalGroup.connectors = [Array]$generalConnectorExcludingSpecifiedConnector

        Set-DlpPolicy -PolicyName $policy.name -UpdatedPolicy $policy
        Write-Host $policy.connectorGroups
    }
    elseif ($connectorInConfidential -ne $null -and $DlpPolicy.GroupName -eq 'NonBusinessDataGroup')
    {
        Write-Host "Move connector $($DlpPolicy.ConnectorName) from BusinessDataGroup to NonBusinessDataGroup." -ForegroundColor Green
        
        #Add the connector to the non business data group policy
        $generalGroup.connectors += $connectorInConfidential

        #remove the connector from business data group policy
        $confidentialConnectorExcludingSpecifiedConnector = $confidentialGroup.connectors | where { $_.id -ne $DlpPolicy.ConnectorID }
        
        $confidentialGroup.connectors = [Array]$confidentialConnectorExcludingSpecifiedConnector

        Set-DlpPolicy -PolicyName $policy.name -UpdatedPolicy $policy
        Write-Host $policy.connectorGroups
    }
    elseif ($connectorInConfidential -ne $null -and $DlpPolicy.GroupName -eq 'BlockedGroup') 
    {
        Write-Host "Move connector $($DlpPolicy.ConnectorName) from BusinessDataGroup to BlockedGroup." -ForegroundColor Green

        #Add the connector to the blocked data group policy
        $blockedGroup.connectors += $connectorInConfidential

        #remove the connector from business data group policy
        $confidentialConnectorExcludingSpecifiedConnector = $confidentialGroup.connectors | where { $_.id -ne $DlpPolicy.ConnectorID }
        
        $confidentialGroup.connectors = [Array]$confidentialConnectorExcludingSpecifiedConnector

        Set-DlpPolicy -PolicyName $policy.name -UpdatedPolicy $policy
        Write-Host $policy.connectorGroups
    }
    elseif ($connectorInBlocked -ne $null -and $DlpPolicy.GroupName -eq 'NonBusinessDataGroup')
    {
        Write-Host "Move connector $($DlpPolicy.ConnectorName) from BlockedGroup to NonBusinessDataGroup." -ForegroundColor Green
        
        #Add the connector to the non business data group policy
        $generalGroup.connectors += $connectorInBlocked

        #remove the connector from business data group policy
        $blockedConnectorExcludingSpecifiedConnector = $blockedGroup.connectors | where { $_.id -ne $DlpPolicy.ConnectorID }
        
        $blockedGroup.connectors = [Array]$blockedConnectorExcludingSpecifiedConnector

        Set-DlpPolicy -PolicyName $policy.name -UpdatedPolicy $policy
        Write-Host $policy.connectorGroups
    }
    elseif ($connectorInBlocked -ne $null -and $DlpPolicy.GroupName -eq 'BusinessDataGroup') 
    {
        Write-Host "Move connector $($DlpPolicy.ConnectorName) from BlockedGroup to BusinessDataGroup." -ForegroundColor Green

        #Add the connector to the blocked data group policy
        $confidentialGroup.connectors += $connectorInBlocked

        #remove the connector from business data group policy
        $blockedConnectorExcludingSpecifiedConnector = $blockedGroup.connectors | where { $_.id -ne $DlpPolicy.ConnectorID }
        
        $blockedGroup.connectors = [Array]$blockedConnectorExcludingSpecifiedConnector

        Set-DlpPolicy -PolicyName $policy.name -UpdatedPolicy $policy
        Write-Host $policy.connectorGroups
    }
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

Write-Host "Loading DLP CSV File" -ForegroundColor Green
$dlpPolicies = Import-Csv -Path $csvPath

Write-Host "Updating DLP Policy" -ForegroundColor Green
$dlpPolicies | ? {$_.Action -eq "Update"} | % {Update-DlpPolicy -DLPPolicy $_}

Write-Host "Completed" -ForegroundColor Green