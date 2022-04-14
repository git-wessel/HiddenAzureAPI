<#
    .SYNOPSIS
    Get a graph or other Azure token if needed (e.g. https://main.iam.ad.ext.azure.com)

    This script is not guaranteed and may not be used for commercial purposes without prior permission from the author. 
    It is suitable for scenarios where an Azure token is required to automate operations that a service principal cannot.
    
    .EXAMPLE
    $graphToken = get-azResourceTokenSilentlyWithoutModuleDependencies -userUPN wesley@techblik.nl
    .PARAMETER userUPN
    the UPN of the user you need a token for (that is MFA enabled or protected by a CA policy)
    .PARAMETER refreshTokenCachePath
    Path to encrypted token cache if you don't want to use the default
    .PARAMETER tenantId
    If supplied, logs in to specified tenant, optional and only required if you're using Azure B2B
    .PARAMETER resource
    Resource your token is for, e.g. "https://graph.microsoft.com" would give a token for the Graph API

    .NOTES
    filename: ./API main.iam.ad.ext.azure.com.ps1
    author: Wesley
    blog: techblik.nl
    created: 14-04-2022

#>
Param(
    $refreshTokenCachePath=(Join-Path $env:APPDATA -ChildPath "azRfTknCache.cf"),
    $refreshToken,
    $tenantId,
    [Parameter(Mandatory=$true)]$userUPN,
    $resource="https://main.iam.ad.ext.azure.com",
    $clientId="1950a258-227b-4e31-a9cf-717495945fc2" #use 1b730954-1685-4b74-9bfd-dac224a7b894 for audit/sign in logs or other things that only work through the AzureAD module, use d1ddf0e4-d672-4dae-b554-9d5bdfd93547 for Intune
)

if(!$tenantId){
    $tenantId = (Invoke-RestMethod "https://login.windows.net/$($userUPN.Split("@")[1])/.well-known/openid-configuration" -Method GET).userinfo_endpoint.Split("/")[3]
}

if($refreshToken){
    try{
        write-verbose "checking provided refresh token and updating it"
        $response = (Invoke-RestMethod "https://login.windows.net/$tenantId/oauth2/token" -Method POST -Body "grant_type=refresh_token&refresh_token=$refreshToken" -ErrorAction Stop)
        $refreshToken = $response.refresh_token
        write-verbose "refresh and access token updated"
    }catch{
        Write-Output "Failed to use cached refresh token, need interactive login or token from cache"   
        $refreshToken = $False 
    }
}

if([System.IO.File]::Exists($refreshTokenCachePath) -and !$refreshToken){
    try{
        write-verbose "getting refresh token from cache"
        $refreshToken = Get-Content $refreshTokenCachePath -ErrorAction Stop | ConvertTo-SecureString -ErrorAction Stop
        $refreshToken = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($refreshToken)
        $refreshToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($refreshToken)
        $response = (Invoke-RestMethod "https://login.windows.net/$tenantId/oauth2/token" -Method POST -Body "grant_type=refresh_token&refresh_token=$refreshToken" -ErrorAction Stop)
        $refreshToken = $response.refresh_token
        write-verbose "tokens updated using cached token"
    }catch{
        Write-Output "Failed to use cached refresh token, need interactive login"
        $refreshToken = $False
    }
}

#full login required
if(!$refreshToken){
    Write-Verbose "No cache file exists and no refresh token supplied, we have to perform interactive logon"
    if ([Environment]::UserInteractive) {
        foreach ($arg in [Environment]::GetCommandLineArgs()) {
            if ($arg -like '-NonI*') {
                Throw "Interactive login required, but script is not running interactively. Run once interactively or supply a refresh token with -refreshToken"
            }
        }
    }

    try{
        Write-Verbose "Attempting device sign in method"
        $response = Invoke-RestMethod -Method POST -UseBasicParsing -Uri "https://login.microsoftonline.com/$tenantId/oauth2/devicecode" -ContentType "application/x-www-form-urlencoded" -Body "resource=https%3A%2F%2Fmain.iam.ad.ext.azure.com&client_id=$clientId"
        Write-Output $response.message
        $waited = 0
        while($true){
            try{
                $authResponse = Invoke-RestMethod -uri "https://login.microsoftonline.com/$tenantId/oauth2/token" -ContentType "application/x-www-form-urlencoded" -Method POST -Body "grant_type=device_code&resource=https%3A%2F%2Fmain.iam.ad.ext.azure.com&code=$($response.device_code)&client_id=$clientId" -ErrorAction Stop
                $refreshToken = $authResponse.refresh_token
                break
            }catch{
                if($waited -gt 300){
                    Write-Verbose "No valid login detected within 5 minutes"
                    Throw
                }
                #try again
                Start-Sleep -s 5
                $waited += 5
            }
        }
    }catch{
        Throw "Interactive login failed, cannot continue"
    }
}

if($refreshToken){
    write-verbose "caching refresh token"
    Set-Content -Path $refreshTokenCachePath -Value ($refreshToken | ConvertTo-SecureString -AsPlainText -Force -ErrorAction Stop | ConvertFrom-SecureString -ErrorAction Stop) -Force -ErrorAction Continue | Out-Null
    write-verbose "refresh token cached"
}else{
    Throw "No refresh token found in cache and no valid refresh token passed or received after login, cannot continue"
}

#Acquire token with correct resource ID
try{
    write-verbose "update token for supplied resource"
    $response = (Invoke-RestMethod "https://login.windows.net/$tenantId/oauth2/token" -Method POST -Body "resource=74658136-14ec-4630-ad9b-26e160ff0fc6&grant_type=refresh_token&refresh_token=$refreshToken&client_id=$clientId&scope=openid" -ErrorAction Stop)
    $resourceToken = $response.access_token
    write-verbose "token translated to $resource"
}catch{
    Throw "Failed to translate access token to $resource , cannot continue"
}

$Headers = @{
        "Authorization" = "Bearer " + $resourceToken
        "Content-type"  = "application/json"
        "X-Requested-With" = "XMLHttpRequest"
        "x-ms-client-request-id" = [guid]::NewGuid()
        "x-ms-correlation-id" = [guid]::NewGuid()
    }

$url = "https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies"
$content = '{"objectId":"default","enablementType":2,"numberOfAuthenticationMethodsRequired":1,"emailOptionEnabled":true,"mobilePhoneOptionEnabled":true,"officePhoneOptionEnabled":false,"securityQuestionsOptionEnabled":false,"mobileAppNotificationEnabled":false,"mobileAppCodeEnabled":false,"numberOfQuestionsToRegister":5,"numberOfQuestionsToReset":3,"registrationRequiredOnSignIn":true,"registrationReconfirmIntevalInDays":180,"skipRegistrationAllowed":true,"skipRegistrationMaxAllowedDays":7,"customizeHelpdeskLink":true,"customHelpdeskEmailOrUrl":"https://techblik.nl","notifyUsersOnPasswordReset":true,"notifyOnAdminPasswordReset":false,"passwordResetEnabledGroupIds":[],"passwordResetEnabledGroupName":"","securityQuestions":[],"registrationConditionalAccessPolicies":[],"emailOptionAllowed":true,"mobilePhoneOptionAllowed":true,"officePhoneOptionAllowed":true,"securityQuestionsOptionAllowed":true,"mobileAppNotificationOptionAllowed":true,"mobileAppCodeOptionAllowed":true}'

Invoke-RestMethod -Uri $url -Headers $Headers -Method PUT -Body $content -ErrorAction Stop
 