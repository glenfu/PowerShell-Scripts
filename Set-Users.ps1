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

#Set-Users.ps1
#How to run script: .\Set-Users -AdminUsername <admin username> -AdminPassword <password> -csvPath <csv filepath with extension>
Param(
    [string] [Parameter(Mandatory = $true)]  $AdminUsername,
    [string] [Parameter(Mandatory = $true)]  $AdminPassword,
    [string] [Parameter(Mandatory = $true)]  $csvPath
)

Function New-UserFromCsv
{
    param
    (   
        [PSObject]$User,
        [String]$TenantName
    )

    $userPrincipalName = $User.UserPrincipalName

    Write-Output "Retrieve user $userPrincipalName" 
    $checkUser =  Get-AzureADUser -SearchString $userPrincipalName
    $crmLicenseName="DYN365_ENTERPRISE_PLAN1"
    $officeLicenseName="ENTERPRISEPREMIUM"
    
    if($checkUser -ne $null)
    {
        Write-Output "User $userPrincipalName Found. Checking CRM and Office License"
        
        if ($checkUser.AccountEnabled -eq $false)
        {
            Write-Output "Enabling user: $userPrincipalName"
            Set-AzureADUser -ObjectID $userPrincipalName -AccountEnabled $true
        }

        $license = Get-AzureADUserLicenseDetail -ObjectId $checkUser.ObjectId

        if($license -eq $null)
        {
            Setup-User -User $User
        }
        else
        {
            Write-Output "User $userPrincipalName already exists and has CRM and Office license"
        }
    }
    else
    {
        Write-Output "Creating User $UserDisplayName" 

        $userPWProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
        $userPWProfile.Password = $User.Password
        $userPWProfile.EnforceChangePasswordPolicy = $false
        $userPWProfile.ForceChangePasswordNextLogin = $false

        $newUser = New-AzureADUser `
            -DisplayName $User.DisplayName -GivenName $User.FirstName -SurName $User.LastName `
            -UserPrincipalName $User.UserPrincipalName `
            -UsageLocation $User.UsageLocation `
            -MailNickName $User.MailNickName `
            -PasswordProfile $userPWProfile `
            -AccountEnabled $true

        Setup-User -User $User
    }
}

Function Setup-User
{
    param
    (   
        [PSObject]$User
    )    

    Write-Host "(6/12) Assigning user licenses... " -ForegroundColor Green
    Assign-UserLicenses -User $User
    
    Write-Host "(7/12) Adding user to group... " -ForegroundColor Green
    $newUser = Get-AzureADUser -SearchString $User.userPrincipalName
    Add-UserToGroup -User $User -UserID $newUser.ObjectId

    #force sync for the new user to the environment
    Write-Host "(8/12) Force sync new user to environment... " -ForegroundColor Green
    $environmentName = $User.EnvironmentName
    $environment = Get-AdminPowerAppEnvironment "*$environmentName*"
    Add-AdminPowerAppsSyncUser -EnvironmentName $environment.EnvironmentName -PrincipalObjectId $newUser.ObjectId
    
    Write-Host "(9/12) Confirm if User Account is Enabled... " -ForegroundColor Green
    Confirm-CrmUserCreation -EnvironmentName $environment.EnvironmentName -User $User -UserID $newUser.ObjectId

    Write-Host "(10/12) Move Crm User to BusinessUnit... " -ForegroundColor Green
    Move-CrmUserBusinessUnit -User $User

    Write-Host "(11/12) Assign Security Role to Crm User..." -ForegroundColor Green
    Assign-CrmUserSecurityRole -User $User
}

Function Assign-UserLicenses
{
    param
    (   
        [PSObject]$User
    )    

    $crmLicense = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
    $crmLicense.SkuId = (Get-AzureADSubscribedSku | Where-Object -Property SkuPartNumber -Value $crmLicenseName -EQ).SkuID
    $LicensesToAssign = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
    $LicensesToAssign.AddLicenses = $crmLicense
    Set-AzureADUserLicense -ObjectId $User.userPrincipalName -AssignedLicenses $LicensesToAssign
    $officeLicense = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
    $officeLicense.SkuId = (Get-AzureADSubscribedSku | Where-Object -Property SkuPartNumber -Value $officeLicenseName -EQ).SkuID
    $LicensesToAssign.AddLicenses = $officeLicense
    Set-AzureADUserLicense -ObjectId $User.userPrincipalName -AssignedLicenses $LicensesToAssign
}

Function Add-UserToGroup
{
    param
    (   
        [PSObject]$User,
        [string]$UserID
    )

    #get security group and add user to the security group
    $groupId = Get-AzureADGroup -SearchString $User.SecurityGroup | Select ObjectId
    Add-AzureADGroupMember -ObjectId $groupId.ObjectId -RefObjectId $UserID
}

Function Move-CrmUserBusinessUnit
{
    param
    (   
        [PSObject]$User
    )

    $domainName = $User.UserPrincipalName
    $systemUserId = ""
    $businessUnitName = $User.BusinessUnitName

    $businessUnit = Get-CrmRecords -EntityLogicalName businessunit -FilterAttribute name -FilterOperator eq -FilterValue $businessUnitName -Fields businessunitid
    
    $query= new-object Microsoft.Xrm.Sdk.Query.QueryExpression('systemuser')
    $query.ColumnSet = new-object -TypeName Microsoft.Xrm.Sdk.Query.ColumnSet($true)
    $query.ColumnSet.AddColumn("fullname");
    $query.Criteria.AddCondition("fullname", [Microsoft.Xrm.Sdk.Query.ConditionOperator]::Equal, $User.DisplayName);

    ForEach ($en In $conn.RetrieveMultiple($query).Entities) { $systemUserId = $en.Id }

    if($businessUnit.CrmRecords.Count -eq 0)
    {
        Write-Error "Business Unit $businessUnitName does not exist"
        return
    }
    else
    {
        Write-Output "Move $domainName to $businessUnitName"
        $businessUnitId = $businessUnit.CrmRecords[0].businessunitid.Guid
        Set-CrmUserBusinessUnit -BusinessUnitId $businessUnitId -UserId $systemUserId -ReassignUserId $systemUserId
        $User.BusinessUnitId = $businessUnitId
    }    
}

Function Assign-CrmUserSecurityRole
{
    param
    (   
        [PSObject]$User
    )

    $domainName = $User.UserPrincipalName
    $securityRoleName = $User.SecurityRoleName.Split("|")
    $systemUserId = ""

    $query= new-object Microsoft.Xrm.Sdk.Query.QueryExpression('systemuser')
    $query.ColumnSet = new-object -TypeName Microsoft.Xrm.Sdk.Query.ColumnSet($true)
    $query.ColumnSet.AddColumn("fullname");
    $query.Criteria.AddCondition("fullname", [Microsoft.Xrm.Sdk.Query.ConditionOperator]::Equal, $User.DisplayName);

    ForEach ($en In $conn.RetrieveMultiple($query).Entities) { $systemUserId = $en.Id }

    ForEach ($securityRole in $securityRoleName)
    {
        Write-Output "Assign $securityRole to $domainName"
        Add-CrmSecurityRoleToUser -UserId $systemUserId -SecurityRoleName $securityRole
    }
}
Function Remove-UserFromCsv
{
    param
    (   
        [PSObject]$User
    )

    $userPrincipalName = $User.UserPrincipalName

    Write-Output "Retrieve user $userPrincipalName" 
    $checkUser =  Get-AzureADUser -SearchString $userPrincipalName
    
    if($checkUser -ne $null)
    {
        $securityRoleName = $User.SecurityRoleName.Split("|")

        ForEach ($securityRole in $securityRoleName)
        {
            $UserSourceFetch = "<fetch version=""1.0"" output-format=""xml-platform"" mapping=""logical"" distinct=""true"">
                <entity name=""role"">
                <attribute name=""name"" />
                <attribute name=""businessunitid"" />
                <attribute name=""roleid"" />
                <filter type=""and"">
                    <condition attribute=""name"" operator=""eq"" value=""$securityRole"" />
                </filter>
                <link-entity name=""systemuserroles"" from=""roleid"" to=""roleid"" visible=""false"" intersect=""true"">
                    <link-entity name=""systemuser"" from=""systemuserid"" to=""systemuserid"" alias=""user"">
                    <attribute name=""systemuserid"" />
                    <attribute name=""domainname"" />
                    <filter type=""and"">
                        <condition attribute=""domainname"" operator=""eq"" value=""$userPrincipalName""/>
                    </filter>
                    </link-entity>
                </link-entity>
                </entity>
            </fetch>";

            #Get users roles along with other info
            $list = (Get-CrmRecordsByFetch -Fetch $UserSourceFetch -conn $conn).CrmRecords | Select `
                name, `
                roleid,
                @{Name="businessunitid";Expression={$_.businessunitid_Property.Value.Id}}, `
                @{Name="businessunitname";Expression={$_.businessunitid_Property.Value.Name}}, `
                @{Name="systemuserid";Expression={$_."user.systemuserid"}}, `
                @{Name="domainname";Expression={$_."user.domainname"}}

            # |% is a shortcut of "ForEach(item $_ in $list)"
            $list | % { 
                Write-Output "Removing $($_.name) $($_.roleid) from user:$($_.domainname) $($_.systemuserid)"
                #remove security role cmdlet call goes here 
                Remove-CrmSecurityRoleFromUser -UserId $_.systemuserid -SecurityRoleId $_.roleid
            }
        }

        #get security group and add user to the security group
        $groupId = Get-AzureADGroup -SearchString $User.SecurityGroup | Select ObjectId
        Remove-AzureADGroupMember -ObjectId $groupId.ObjectId -MemberId $checkUser.ObjectId

        Write-Output "User $userPrincipalName Found. Checking CRM and Office License"
        $license = Get-AzureADUserLicenseDetail -ObjectId $checkUser.ObjectId
        if($license -eq $null)
        {
            Write-Output "License not assigned."
        }
        else
        {
            Write-Output "User $userPrincipalName already exists and has CRM and Office license"
            $Skus = $checkUser | Select -ExpandProperty AssignedLicenses | Select SkuID
            if($checkUser.Count -ne 0) 
            {
                if($Skus -is [array])
                {
                    $licenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
                    for ($i=0; $i -lt $Skus.Count; $i++) {
                        $Licenses.RemoveLicenses +=  (Get-AzureADSubscribedSku | Where-Object -Property SkuID -Value $Skus[$i].SkuId -EQ).SkuID   
                    }
                    Set-AzureADUserLicense -ObjectId $checkUser.ObjectId -AssignedLicenses $licenses
                } else {
                    $licenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
                    $Licenses.RemoveLicenses =  (Get-AzureADSubscribedSku | Where-Object -Property SkuID -Value $Skus.SkuId -EQ).SkuID
                    Set-AzureADUserLicense -ObjectId $checkUser.ObjectId -AssignedLicenses $licenses
                }
            }
        }

        if ($checkUser.AccountEnabled -eq $true)
        {
            Write-Output "Disabling user: $userPrincipalName"
            Set-AzureADUser -ObjectID $userPrincipalName -AccountEnabled $false
        }
    }
    else
    {
        Write-Output "Unable to retrieve $userPrincipalName" 
    }
}

Function Confirm-CrmUserCreation
{
    param
    (   
        [PSObject]$User,
        [String]$EnvironmentName,
        [String]$UserID
    )

    $domainName = $User.UserPrincipalName

    # Dynamics CRM Online user will be synchronized if Office 365 user has a valid license.
    # As it may take minutes, do retrieve every 5 seconds in while loop.
    while($true)
    {
        $crmUser = Get-CrmRecords -EntityLogicalName systemuser -FilterAttribute domainname -FilterOperator eq -FilterValue $domainName -Fields domainname,isdisabled
        if ($crmUser.CrmRecords[0].isdisabled_Property.Value -eq $True)
        {
            Add-AdminPowerAppsSyncUser -EnvironmentName $EnvironmentName -PrincipalObjectId $UserID
            Start-Sleep -Seconds 5
        }
        else
        {
            #Add-AdminPowerAppsSyncUser -EnvironmentName $EnvironmentName -PrincipalObjectId $UserID
            Write-Output "$domainName is added to CRM system"
            break
        }
    }   
}
#Script Initialization
Write-Host "(1/12) Check and install missing PowerShell Modules..." -ForegroundColor Green

(Get-Module -Name 'AzureAD' -ListAvailable) -or (Install-Module -Name AzureAD -Scope AllUsers -Repository PSGallery -Force -AllowClobber) | Out-Null
(Get-Module -Name 'Microsoft.PowerApps.Administration.PowerShell' -ListAvailable) -or (Install-Module -Name Microsoft.PowerApps.Administration.PowerShell -Scope AllUsers -Repository PSGallery -Force -AllowClobber) | Out-Null
(Get-Module -Name 'Microsoft.PowerApps.PowerShell' -ListAvailable) -or (Install-Module -Name Microsoft.PowerApps.PowerShell -Scope AllUsers -Repository PSGallery -Force -AllowClobber) | Out-Null

$adminPW = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
$adminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($AdminUsername, $adminPW)

Write-Host "(2/12) Connecting to Azure AD as $AdminUsername" -ForegroundColor Green

Try
{
    $connected = Add-PowerAppsAccount -Username $AdminUsername -Password $adminPW
    $connected = Connect-AzureAD -Credential $adminCredential
}
Catch
{
     throw
}

Write-Host "(3/12) Connecting to CRM Online as $AdminUsername" -ForegroundColor Green
$crmCred = New-Object System.Management.Automation.PSCredential ($AdminUsername,$adminPW) 
Try
{
    # You can also use Get-CrmConnection to directly create connection.
    # See https://msdn.microsoft.com/en-us/library/dn756303.aspx for more detail.
    Connect-CrmOnlineDiscovery -Credential $crmCred -ErrorAction Stop
}
Catch
{
     throw
}

Write-Host "(4/12) Loading User CSV File" -ForegroundColor Green
$users = Import-Csv -Path $csvPath

Write-Host "(5/12) Creating Azure AD User" -ForegroundColor Green
$users | ? {$_.Action -eq "New"} | % {New-UserFromCsv -User $_ -TenantName $TenantName}

if (($users | ? {$_.Action -eq "Remove"} | Measure-Object).Count -ne 0)
{
    Write-Host "(12/12) Removing User Security Role, Unassign Security Group and Remove License" -ForegroundColor Green
    $users | ? {$_.Action -eq "Remove"} | % {Remove-UserFromCsv -User $_}
}

Write-Host "Completed" -ForegroundColor Green