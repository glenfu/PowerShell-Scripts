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

#Create-BulkDeleteJob.ps1
#How to run script: .\Create-BulkDeleteJob.ps1 -ApplicationID <Application ID> -ClientSecret <client secret> -ServerURL <https://xxxx.crm.dynamics.com>)

Param(
    [string] [Parameter(Mandatory = $true)]  $ApplicationID,
    [string] [Parameter(Mandatory = $true)]  $ClientSecret,
    [string] [Parameter(Mandatory = $true)]  $ServerURL
)

#Script Initialization
Write-Host "Check and install missing PowerShell Modules..." -ForegroundColor Green

(Get-Module -Name 'Microsoft.Xrm.Data.Powershell' -ListAvailable) -or (Install-Module -Name Microsoft.PowerApps.PowerShell -Scope AllUsers -Repository PSGallery -Force -AllowClobber) | Out-Null

Try
{
    Write-Host "Authenticating as service principal..." -ForegroundColor Green
    $conn = Connect-CrmOnline -OAuthClientId $ApplicationID -ClientSecret $ClientSecret -ServerUrl $ServerURL
}
Catch
{
     throw
}

$qe = new-object Microsoft.Crm.Sdk.Messages.FetchXmlToQueryExpressionRequest 
$qe.FetchXml=@"
<fetch version='1.0' mapping='logical'>
  <entity name='account'>
    <attribute name='accountid' />
    <order attribute='name' descending='false' />
    <filter type='and'>
      <condition attribute='statecode' operator='eq' value='0' />
      <condition attribute='name' operator='eq' value='TEST' />
    </filter>
  </entity>
</fetch>
"@

$qeResponse=$conn.ExecuteCrmOrganizationRequest($qe) 
#TODO Check for failures on $conn.LastCrmError here

$bulkDeleteJobReq = new-object Microsoft.Crm.Sdk.Messages.BulkDeleteRequest 
$bulkDeleteJobReq.JobName = "Glen Bulk Delete Job 1" 
$bulkDeleteJobReq.ToRecipients = @() #none
$bulkDeleteJobReq.CCRecipients = @() #none
$bulkDeleteJobReq.QuerySet=$qeResponse.Query
#Recurrence Patterns Documentation: https://msdn.microsoft.com/en-us/library/gg328511.aspx
$bulkDeleteJobReq.RecurrencePattern = "FREQ=DAILY;"
$bulkDeleteJobReq.RunNow = $false 

#specify bulk delete job start date & time
$bulkDeleteJobReq.StartDateTime = (Get-Date -Date "4/5/2022 08:12:00 AM") 
$bulkDelJobResponse=$conn.ExecuteCrmOrganizationRequest($bulkDeleteJobReq) 

#TODO Check for failures on $conn.LastCrmError here