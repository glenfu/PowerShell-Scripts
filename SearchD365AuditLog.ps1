# Author: Glen Fu
# Date: 27/10/2023
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

#SearchD365AuditLog.ps1
#How to run script: .\SearchD365AuditLog.ps1 -AdminUsername <admin username> -AdminPassword <password> -LogFile <.\AdminLogFile_YYYYMMDDHHMM.txt> -OutputFile <.\AdminOutputFile_YYYYMMDDHHMM.csv> -StartDate (Get-Date<'DD/MM/YYYY HH:MM'>) -EndDate (Get-Date<'DD/MM/YYYY HH:MM'>) -SearchTerm <domain name> -Message <Retrieve contact,RetrieveMultiple contact,ExportToExcel contact> -InstanceUrl <Dynamics 365 environment URL> -EntityName <contact> -AuditMessage <Retrieve;RetrieveMultiple;ExportToExcel>
Param(
    [string] [Parameter(Mandatory = $true)]  $AdminUsername,
    [string] [Parameter(Mandatory = $true)]  $AdminPassword,
    [string] [Parameter(Mandatory = $true)]  $LogFile,
    [string] [Parameter(Mandatory = $true)]  $OutputFile,
    [DateTime] [Parameter(Mandatory = $true)]  $StartDate,
    [DateTime] [Parameter(Mandatory = $true)]  $EndDate,
    [string] [Parameter(Mandatory = $false)]  $SearchTerm,
    [string] [Parameter(Mandatory = $false)]  $Message,
    [string] [Parameter(Mandatory = $false)]  $InstanceUrl,
    [string] [Parameter(Mandatory = $false)]  $EntityName,
    [string] [Parameter(Mandatory = $false)]  $AuditMessage
)

# Required Modules (installed as admin)
Write-Host "Check and install missing ExchangeOnlineManagement Module..." -ForegroundColor Green
(Get-Module -Name 'ExchangeOnlineManagement' -ListAvailable) -or (Install-Module -Name 'ExchangeOnlineManagement' -Scope CurrentUser -Repository PSGallery -Force -AllowClobber) | Out-Null

$adminPW = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
$adminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($AdminUsername, $adminPW)

Try {
    $connected = Connect-ExchangeOnline -Credential $adminCredential
}
Catch {
    throw
}

#Modify the values for the following variables to configure the audit log search.
[DateTime]$start = $StartDate
[DateTime]$end = $EndDate
$record = "CRM"
$resultSize = 5000
$intervalMinutes = 30

#Start script
[DateTime]$currentStart = $start
[DateTime]$currentEnd = $start

Function Write-LogFile ([String]$LogMessage) {
    $final = [DateTime]::Now.ToUniversalTime().ToString("s") + ":" + $LogMessage
    $final | Out-File $LogFile -Append
}

Write-LogFile "BEGIN: Retrieving audit records between $($start) and $($end), RecordType=$record, PageSize=$resultSize."
Write-Host "Retrieving audit records for the date range between $($start) and $($end), RecordType=$record, ResultsSize=$resultSize"

$totalCount = 0
while ($true) {
    $currentEnd = $currentStart.AddMinutes($intervalMinutes)
    if ($currentEnd -gt $end) {
        $currentEnd = $end
    }

    if ($currentStart -eq $currentEnd) {
        break
    }

    $sessionID = [Guid]::NewGuid().ToString() + "_" + "ExtractLogs" + (Get-Date).ToString("yyyyMMddHHmmssfff")
    Write-LogFile "INFO: Retrieving audit records for activities performed between $($currentStart) and $($currentEnd)"
    Write-Host "Retrieving audit records for activities performed between $($currentStart) and $($currentEnd)"
    $currentCount = 0

    do {
        if (-Not [string]::IsNullOrEmpty($Message)) {
            #Filter the audit log records by Messages
            $results = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -ObjectIDs $Message -RecordType $record -SessionId $sessionID -SessionCommand ReturnLargeSet -ResultSize $resultSize
        }
        elseif (-Not[string]::IsNullOrEmpty($SearchTerm)) {
            $results = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -FreeText $SearchTerm -RecordType $record -SessionId $sessionID -SessionCommand ReturnLargeSet -ResultSize $resultSize
        }
        else {
            $results = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -RecordType $record -SessionId $sessionID -SessionCommand ReturnLargeSet -ResultSize $resultSize
        }
        if (-Not [string]::IsNullOrEmpty($InstanceUrl)) {
            #Filter the audit log records by Instance URL provided
            $results = $results | ? { ($_.AuditData | ConvertFrom-Json).InstanceUrl -eq $instanceUrl }
        }
        if (-Not [string]::IsNullOrEmpty($EntityName)) {
            #Filter the audit log records by EntityName provided
            $results = $results | ? { ($_.AuditData | ConvertFrom-Json).EntityName -eq $EntityName }
        }
        if (-Not [string]::IsNullOrEmpty($AuditMessage)) {
            #Filter the audit log records by Messages provided and split into array
            $messages = $AuditMessage -split ';'
            $results = $results | ? { ($_.AuditData | ConvertFrom-Json).Message -in $messages }
        }

        $resultList = @()
        
        foreach ($result in $results) {
            #Convert AuditData (JSON formatted string) to custom object and split into individual columns
            $auditData = $result.AuditData | ConvertFrom-Json
            #Concatenate Fields array into string with comma delimiter
            $auditDataFields = [system.string]::Join(",", $auditData.Fields)
            $resultDetail = New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name Id -Value $auditData.Id `
            | Add-Member -PassThru -MemberType NoteProperty -Name CreationDate -Value $result.CreationDate `
            | Add-Member -PassThru -MemberType NoteProperty -Name Record_Type -Value $result.RecordType `
            | Add-Member -PassThru -MemberType NoteProperty -Name Operations -Value $result.Operations `
            | Add-Member -PassThru -MemberType NoteProperty -Name UserIds -Value $result.UserIds `
            | Add-Member -PassThru -MemberType NoteProperty -Name CreationTime -Value $auditData.CreationTime `
            | Add-Member -PassThru -MemberType NoteProperty -Name Operation -Value $auditData.Operation `
            | Add-Member -PassThru -MemberType NoteProperty -Name OrganizationId -Value $auditData.OrganizationId `
            | Add-Member -PassThru -MemberType NoteProperty -Name RecordType -Value $auditData.RecordType `
            | Add-Member -PassThru -MemberType NoteProperty -Name ResultStatus -Value $auditData.ResultStatus `
            | Add-Member -PassThru -MemberType NoteProperty -Name UserKey -Value $auditData.UserKey `
            | Add-Member -PassThru -MemberType NoteProperty -Name UserType -Value $auditData.UserType `
            | Add-Member -PassThru -MemberType NoteProperty -Name Version -Value $auditData.Version `
            | Add-Member -PassThru -MemberType NoteProperty -Name Workload -Value $auditData.Workload `
            | Add-Member -PassThru -MemberType NoteProperty -Name ClientIP -Value $auditData.ClientIP `
            | Add-Member -PassThru -MemberType NoteProperty -Name ObjectId -Value $auditData.ObjectId `
            | Add-Member -PassThru -MemberType NoteProperty -Name UserId -Value $auditData.UserId `
            | Add-Member -PassThru -MemberType NoteProperty -Name CRMOrganizationUniqueName -Value $auditData.CRMOrganizationUniqueName `
            | Add-Member -PassThru -MemberType NoteProperty -Name Fields -Value $auditDataFields `
            | Add-Member -PassThru -MemberType NoteProperty -Name InstanceUrl -Value $auditData.InstanceUrl `
            | Add-Member -PassThru -MemberType NoteProperty -Name ItemType -Value $auditData.ItemType `
            | Add-Member -PassThru -MemberType NoteProperty -Name ItemUrl -Value $auditData.ItemUrl `
            | Add-Member -PassThru -MemberType NoteProperty -Name UserAgent -Value $auditData.UserAgent `
            | Add-Member -PassThru -MemberType NoteProperty -Name CorrelationId -Value $auditData.CorrelationId `
            | Add-Member -PassThru -MemberType NoteProperty -Name EntityId -Value $auditData.EntityId `
            | Add-Member -PassThru -MemberType NoteProperty -Name EntityName -Value $auditData.EntityName `
            | Add-Member -PassThru -MemberType NoteProperty -Name Message -Value $auditData.Message `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrimaryFieldValue -Value $auditData.PrimaryFieldValue `
            | Add-Member -PassThru -MemberType NoteProperty -Name Query -Value $auditData.Query `
            | Add-Member -PassThru -MemberType NoteProperty -Name QueryResults -Value $auditData.QueryResults `
            | Add-Member -PassThru -MemberType NoteProperty -Name ServiceContextId -Value $auditData.ServiceContextId `
            | Add-Member -PassThru -MemberType NoteProperty -Name ServiceContextIdType -Value $auditData.ServiceContextIdType `
            | Add-Member -PassThru -MemberType NoteProperty -Name ServiceName -Value $auditData.ServiceName `
            | Add-Member -PassThru -MemberType NoteProperty -Name SystemUserId -Value $auditData.SystemUserId `
            | Add-Member -PassThru -MemberType NoteProperty -Name UserUpn -Value $auditData.UserUpn
            
            $resultList += $resultDetail
        }

        if (($resultList | Measure-Object).Count -ne 0) {
            $resultList | export-csv -Path $OutputFile -Append -NoTypeInformation

            $currentTotal = $resultList.Count
            $totalCount += $resultList.Count
            $currentCount += $resultList.Count
            Write-LogFile "INFO: Retrieved $($currentCount) audit records out of the total $($currentTotal)"

            if ($currentTotal -eq $resultList.Count) {
                $logmessage = "INFO: Successfully retrieved $($currentTotal) audit records for the current time range. Moving on!"
                Write-LogFile $logmessage
                Write-Host "Successfully retrieved $($currentTotal) audit records for the current time range. Moving on to the next interval." -foregroundColor Yellow
                ""
                break
            }
        }
    }
    while (($resultList | Measure-Object).Count -ne 0)

    $currentStart = $currentEnd
}

Write-LogFile "END: Retrieving audit records between $($start) and $($end), RecordType=$record, PageSize=$resultSize, total count: $totalCount."
Write-Host "Script complete! Finished retrieving audit records for the date range between $($start) and $($end). Total count: $totalCount" -foregroundColor Green