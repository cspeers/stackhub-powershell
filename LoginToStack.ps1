#Requires -Modules @{ ModuleName="Azure.Storage"; ModuleVersion="4.5.0"},@{ModuleName='AzureRM.Storage';ModuleVersion='5.0.4'}
[CmdletBinding()]
param
(
    [Parameter()]
    [string]$StartPath
)

Function Connect-AzsEnvironment
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ParameterSetName='Uri',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ServicePrincipalUri',ValueFromPipelineByPropertyName=$true)]
        [uri]$FrontDoor,
        [Parameter(Mandatory=$true,ParameterSetName='string',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ServicePrincipalFQDN',ValueFromPipelineByPropertyName=$true)]
        [string]$RegionFQDN,
        [Parameter(Mandatory=$false,ParameterSetName='string',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ServicePrincipalFQDN',ValueFromPipelineByPropertyName=$true)]
        [switch]$Admin,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]$EnvironmentName,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [pscredential]$Credential,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [Alias('Disconnected')]
        [switch]$Adfs,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='ServicePrincipalUri')]
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='ServicePrincipalFQDN')]
        [switch]$ServicePrincipal,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='ServicePrincipalUri')]
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='ServicePrincipalFQDN')]
        [string]$TenantId

    )

    if($PSCmdlet.ParameterSetName -eq 'string')
    {
        if($Admin.IsPresent) {
            $FrontDoor=New-Object Uri("https://adminmanagement.$RegionFQDN")
        }
        else {
            $FrontDoor=New-Object Uri("https://management.$RegionFQDN")
        }
    }
    
    if($FrontDoor.Host -like "*adminmanagement.*")
    {
        $VaultSuffix="adminvault.$($FrontDoor.Host.Substring($FrontDoor.DnsSafeHost.IndexOf('.')+1))"
        $VaultSuffix = $VaultSuffix.Replace('azure.com','azure.net')
    }
    else
    {
        $VaultSuffix="vault.$($FrontDoor.Host.Substring($FrontDoor.DnsSafeHost.IndexOf('.')+1))"
        $VaultSuffix = $VaultSuffix.Replace('azure.com','azure.net')
    }

    if ([string]::IsNullOrEmpty($EnvironmentName)) {
        $pieces=$FrontDoor.DnsSafeHost.Split('.')
        $EnvironmentName="$([string]::Join('',($pieces|Select-Object -Skip 1)))"
        if($pieces[0] -contains 'admin')
        {
            $EnvironmentName="$([string]::Join('',($pieces|Select-Object -Skip 1)))-Admin"
        }
    }

    $EndPoints=Get-ArmEndpoints $FrontDoor
    $Audience=$($EndPoints.authentication.audiences|Select-Object -First 1)
    Write-Information "Environment Name:${EnvironmentName} FrontDoor:${FrontDoor} Targeting Audience:${Audience}"
    $ExistingEnvironment=Get-AzureRmEnvironment -Name $EnvironmentName -ErrorAction SilentlyContinue
    $AddEnvironment=$true
    if($null -ne $ExistingEnvironment)
    {
        Write-Information "Found an existing environment $EnvironmentName"
        if($ExistingEnvironment.ResourceManagerUrl -ne $FrontDoor.AbsoluteUri)
        {
            Write-Information "Existing Frontdoor does not match for $EnvironmentName"
            Remove-AzureRmEnvironment -Name $EnvironmentName -Confirm:$false
            $AddEnvironment=$true
        }
        else
        {
            Write-Information "Existing Environment $EnvironmentName matches front door $FrontDoor"
            $AddEnvironment=$false
        }
    }

    if($AddEnvironment)
    {
        Write-Information "Adding AzureRM Environment $EnvironmentName"
        Add-AzureRmEnvironment -Name $EnvironmentName `
            -ResourceManagerEndpoint $FrontDoor.AbsoluteUri `
            -ManagementPortalUrl $EndPoints.portalEndpoint `
            -GalleryEndpoint $EndPoints.galleryEndpoint `
            -ActiveDirectoryEndpoint $EndPoints.authentication.loginEndpoint `
            -GraphEndpointResourceId $EndPoints.graphEndpoint -GraphEndpoint $EndPoints.graphEndpoint `
            -ActiveDirectoryServiceEndpointResourceId $Audience `
            -EnableAdfsAuthentication:$Adfs.IsPresent
        Set-AzureRmEnvironment -Name $EnvironmentName -AzureKeyVaultDnsSuffix $VaultSuffix|Out-Null
        Set-AzureRmEnvironment -Name $EnvironmentName -AzureKeyVaultServiceEndpointResourceId "https://${VaultSuffix}"|Out-Null
    }
    if($Credential -ne $null)
    {
        Write-Information "Logging into $EnvironmentName as $($Credential.UserName)"
        if($PSCmdlet.ParameterSetName -in 'ServicePrincipalUri','ServicePrincipalFQDN')
        {
            Login-AzureRmAccount -EnvironmentName $EnvironmentName -Credential $Credential -Tenant $TenantId -ServicePrincipal
        }
        else
        {
            Login-AzureRmAccount -EnvironmentName $EnvironmentName -Credential $Credential    
        }
        
    }
}

Function Get-ArmEndpoints
{
    [Parameter()]
    param
    (
        [Parameter(Mandatory)]
        [Uri]$FrontDoor,
        [Parameter()]
        [string]$ApiVersion='2016-09-01'
    )
    $EndUriBld=New-Object UriBuilder($FrontDoor)
    $EndUriBld.Path='/metadata/endpoints'
    $EndUriBld.Query="api-version=$ApiVersion"
    $EndPoints=Invoke-RestMethod -UseBasicParsing -Uri $EndUriBld.Uri
    Write-Output $EndPoints
}

Function Get-Credential
{
    [CmdletBinding(DefaultParameterSetName='MessageSet')]
    param
    (
        [Parameter(ParameterSetName='CredentialSet',Position=0,Mandatory=$true)]
        [PSCredential]$Credential,
        [Parameter(ParameterSetName='MessageSet')]
        [String]$UserName
    )
    if($PSCmdlet.ParameterSetName -eq 'MessageSet')
    {
        if([string]::IsNullOrEmpty($UserName))
        {
            $UserName=Read-Host -Prompt 'Enter the User Name'
        }
        $Password=Read-Host -Prompt 'Enter the Password' -AsSecureString
        $Credential=New-Object PSCredential $UserName,$Password
    }
    Write-Output $Credential
}

if (-not [string]::IsNullOrEmpty($StartPath)) {
    if (Test-Path $StartPath) {
        Set-Location $StartPath
    }
}

Write-Host "Run Connect-AzsEnvironment to get started..."