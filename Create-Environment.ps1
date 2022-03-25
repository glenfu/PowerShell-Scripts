#Update usernames from 1 to 24
#Create trial environments for each user from 1 to 24 for CDX tenant provisioning
#Create-Environment.ps1

Param(
    [string] [Parameter(Mandatory = $true)]  $AdminUsername,
    [string] [Parameter(Mandatory = $true)]  $AdminPassword,
    [string] [Parameter(Mandatory = $true)]  $TenantName,
    [int]    [Parameter(Mandatory = $false)] $UserStartingIndex = 1,
    [string] [Parameter(Mandatory = $false)] $UsageLocation = "SG",
    [string] [Parameter(Mandatory = $false)] $ResourceLocation = "asia"
)

# Install modules
Write-Host "(1/5) Installing PowerShell modules ..." -ForegroundColor Green

Write-Host "Installing Az ..."
Install-Module -Name Az -Scope AllUsers -Repository PSGallery -Force -AllowClobber

Write-Host "Installing AzureAD ..."
Install-Module -Name AzureAD -Scope AllUsers -Repository PSGallery -Force -AllowClobber

Write-Host "Installing Microsoft.PowerApps.Administration.PowerShell ..."
Install-Module -Name Microsoft.PowerApps.Administration.PowerShell -Scope AllUsers -Repository PSGallery -Force -AllowClobber

Write-Host "Installing Microsoft.PowerApps.PowerShell ..."
Install-Module -Name Microsoft.PowerApps.PowerShell -Scope AllUsers -Repository PSGallery -Force -AllowClobber

Write-Host "-=-=-=- PowerShell modules installed -=-=-=-" -ForegroundColor Blue -BackgroundColor White
Write-Host "`r`n"

# Login to Power Apps
Write-Host "(2/5) Logging into Power Apps ..." -ForegroundColor Green

$adminUpn = "$AdminUsername@$TenantName.onmicrosoft.com"
$adminPW = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
$adminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($adminUpn, $adminPW)

$connected = Add-PowerAppsAccount -Username $adminUpn -Password $adminPW

Write-Host "-=-=-=- Power Apps logged in -=-=-=-" -ForegroundColor Blue -BackgroundColor White
Write-Host "`r`n"

# Login to AzureAD
Write-Host "(3/5) Logging into Azure AD ..." -ForegroundColor Green

$connected = Connect-AzureAD -Credential $adminCredential

# Update user accounts
Write-Host "(4/5) Updating user accounts ..." -ForegroundColor Green

$userPWProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$userPWProfile.Password = "Passw0rd!"
$userPWProfile.EnforceChangePasswordPolicy = $false
$userPWProfile.ForceChangePasswordNextLogin = $false

Get-AzureADUser -All $true | 
Where-Object -FilterScript { $_.DisplayName -notmatch '(Microsoft Service Account|System Administrator)' } | 
ForEach-Object {
    $user = Set-AzureADUser -ObjectId $($_.ObjectId) -DisplayName $("user" + $UserStartingIndex) -GivenName $("user") -Surname $UserStartingIndex -UserPrincipalName $("user" + $UserStartingIndex + "@$TenantName.onmicrosoft.com") -MailNickName $("user" + $UserStartingIndex) -PasswordProfile $userPWProfile -AccountEnabled $true
    $UserStartingIndex += 1
    Write-Host $_.DisplayName
}

<# # Delete trial environments
Write-Host "Deleting trial environments ..." -ForegroundColor Green

Get-AzureADUser -All $true | 
Where-Object -FilterScript { $_.DisplayName -notmatch '(Microsoft Service Account|System Administrator)' } | 
ForEach-Object {
    $userPW = ConvertTo-SecureString $userPWProfile.Password -AsPlainText -Force
    $userCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($_.UserPrincipalName, $userPW)
    $userConnected = Add-PowerAppsAccount -Username $_.UserPrincipalName -Password $userPW
    Write-Host $userConnected
    $trialEnvironment = Remove-AdminPowerAppEnvironment -EnvironmentName $_.DisplayName
    Write-Host $trialEnvironment
} #>

# Create trial environments
Write-Host "(5/5) Creating trial environments ..." -ForegroundColor Green

Get-AzureADUser -All $true | 
Where-Object -FilterScript { $_.DisplayName -notmatch '(Microsoft Service Account|System Administrator)' } | 
ForEach-Object {
    $userPW = ConvertTo-SecureString $userPWProfile.Password -AsPlainText -Force
    $userCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($_.UserPrincipalName, $userPW)
    $userConnected = Add-PowerAppsAccount -Username $_.UserPrincipalName -Password $userPW
    Write-Host $_.DisplayName
    $trialEnvironment = New-AdminPowerAppEnvironment -DisplayName $_.DisplayName -Location asia -EnvironmentSku Trial -ProvisionDatabase -CurrencyName SGD -LanguageName 1033 
    Write-Host $trialEnvironment
}