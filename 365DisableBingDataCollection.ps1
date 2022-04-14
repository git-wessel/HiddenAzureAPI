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
    filename: ./365DisableBingDataCollection.ps1
    author: Wesley
    blog: techblik.nl
    created: 14-04-2022

#>

Param(
    [Parameter(Mandatory=$true)]$userUPN,
    $resource="https://admin.microsoft.com",
    $clientId="1950a258-227b-4e31-a9cf-717495945fc2" #use 1b730954-1685-4b74-9bfd-dac224a7b894 for audit/sign in logs or other things that only work through the AzureAD module, use d1ddf0e4-d672-4dae-b554-9d5bdfd93547 for Intune, Use 1950a258-227b-4e31-a9cf-717495945fc2 for Azure Powershell
)
. .\GenericAPITokenAcquire.ps1 -userUPN $userUPN -resource $resource;

$Headers = @{
        "Authorization" = "Bearer " + $resourceToken
        "Content-type"  = "application/json"
        "X-Requested-With" = "XMLHttpRequest"
        "x-ms-client-request-id" = [guid]::NewGuid()
        "x-ms-correlation-id" = [guid]::NewGuid()
    }

$url = "https://admin.microsoft.com/admin/api/settings/security/bingdatacollection"
$content = '{"IsBingDataCollectionConsented": false}'

try {Invoke-RestMethod -Uri $url -Headers $Headers -Method POST -Body $content -ErrorAction Stop}
catch {"Something went wrong while disabling Bing data collection, this is probbaly still enabled. Reference: https://admin.microsoft.com/Adminportal/Home#/Settings/SecurityPrivacy/:/Settings/L1/BingDataCollections"}
Write-Host "Done!" -ForegroundColor "Green"