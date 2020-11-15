#REQUIRES -RunAsAdministrator
#REQUIRES -Modules 'PKI','Posh-ACME'
[CmdletBinding()]
param
(
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.IO.DirectoryInfo]$CertificatePath=(Get-Item $env:TEMP),
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
    [String]$ExternalFQDN,
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [Switch]$IsAdfs,
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [Switch]$CreatePAAS,
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [Switch]$PAASOnly,
    [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
    [ValidateSet(2048, 4096, 8192)]
    [int]$KeyLength = 2048,
    [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
    [ValidateSet('SHA256', 'SHA384', 'SHA512')]
    [string]$HashAlgorithm = 'SHA256',
    [Parameter(ValueFromPipelineByPropertyName=$true,Mandatory=$true)]
    [string]$SubscriptionId,
    [Parameter(ValueFromPipelineByPropertyName=$true,Mandatory=$true)]
    [string]$ClientId,
    [Parameter(ValueFromPipelineByPropertyName=$true,Mandatory=$true)]
    [string]$ClientSecret,
    [Parameter(ValueFromPipelineByPropertyName=$true,Mandatory=$true)]
    [string]$TenantId,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
    [SecureString]$CertificatePassword,
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [PSCustomObject]$LEAccount=(Get-PAAccount),
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [PSCustomObject]$LEServer=(Get-PAServer)
)
 
#region Main Block

Write-Information "Creating Azure Stack Let's Encrypt Certificate Set for $ExternalFQDN ADFS:$IsAdfs PaaS:$CreatePAAS"
#region Constants

$Constants = [PSCustomObject]@{
    X500NameFlags    = "X500NameFlags = 0x40000000`n`r";
    RequestInf       = @"
[Version] 
Signature="`$Windows NT`$"

[NewRequest] 
Subject = "{0}"

Exportable = TRUE                   ; Private key is not exportable 
KeyLength = {1}                     ; Common key sizes: 512, 1024, 2048, 4096, 8192, 16384 
KeySpec = 1                         ; AT_KEYEXCHANGE 
KeyUsage = 0xA0                     ; Digital Signature, Key Encipherment 
MachineKeySet = True                ; The key belongs to the local computer account 
ProviderName = "Microsoft RSA SChannel Cryptographic Provider" 
ProviderType = 12 
SMIME = FALSE 
RequestType = PKCS10
HashAlgorithm = {2}

; At least certreq.exe shipping with Windows Vista/Server 2008 is required to interpret the [Strings] and [Extensions] sections below

[Strings] 
szOID_SUBJECT_ALT_NAME2 = "2.5.29.17" 
szOID_ENHANCED_KEY_USAGE = "2.5.29.37" 
szOID_PKIX_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1" 
szOID_PKIX_KP_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"

[Extensions] 
%szOID_SUBJECT_ALT_NAME2% = "{{text}}{3}"
%szOID_ENHANCED_KEY_USAGE% = "{{text}}%szOID_PKIX_KP_SERVER_AUTH%,%szOID_PKIX_KP_CLIENT_AUTH%"

[RequestAttributes]
"@;
    MandatoryCerts   = @(
        @{Name = "Admin Portal"; Value = "adminportal" },

        @{Name = "Public Portal"; Value = "portal" },

        @{Name = "KeyVault"; Value = "*.vault" },

        @{Name = "KeyVaultInternal"; Value = "*.adminvault" },

        @{Name = "ARM Admin"; Value = "adminmanagement" },

        @{Name = "ARM Public"; Value = "management" },

        @{Name = "ACSBlob"; Value = "*.blob" },

        @{Name = "ACSTable"; Value = "*.table" },

        @{Name = "ACSQueue"; Value = "*.queue" },

        @{Name = "Admin Extension Host"; Value = "*.adminhosting" },

        @{Name = "Public Extension Host"; Value = "*.hosting" }
    );
    AdfsCerts        = @(
        @{Name = "ADFS"; Value = "adfs" },
        @{Name = "Graph"; Value = "graph" }
    );
    PaaSCerts        = @(
        @{Name = "DBAdapter"; Value = "*.dbadapter" },
        @{Name = "AppServiceDefault"; Value = "*.appservice", "*.scm.appservice", "*.sso.appservice" }
        @{Name = "AppServiceAPI"; Value = "api.appservice" },
        @{Name = "AppServiceFTP"; Value = "ftp.appservice" },
        @{Name = "AppServiceSSO"; Value = "sso.appservice" },
        @{Name = 'EventHub'; Value = "eventhub", "*.eventhub" },
        @{Name = 'IOTHub'; Value = "*.mgmtiothub" },
        @{Name = 'DataboxEdge'; Value = "*.databoxedge", "*.databoxedge" }
    );
}

#endregion

#region Input Validation

if([string]::IsNullOrEmpty($SubscriptionId)){throw "You must specify a SubscriptionId"}
if([string]::IsNullOrEmpty($ClientId)){throw "You must specify a ClientId"}
if([string]::IsNullOrEmpty($ClientSecret)){throw "You must specify a ClientSecret"}
#Make sure Posh-ACME has been initialized...
if($null -eq $LEServer){throw "We need a PoSH ACME Server Set! Run Set-PAServer."}
if($null -eq $LEAccount){throw "We need a PoSH ACME Account! Run New-PAAccount."}

#Make sure it exists maybe try and create it...
if(-not $CertificatePath.Exists)
{
    Write-Warning "$($CertificatePath.FullName) does not exist. Attempting to create..."
    $CertificatePath=New-Item -Path (Split-Path $CertificatePath.FullName -Parent) -Name (Split-Path $CertificatePath.FullName -Leaf) -ItemType Directory
    if(-not $CertificatePath.Exists)
    {
        throw "$($CertificatePath.FullName) does not exist!"
    }
}

$OutputPath=Join-Path $CertificatePath.FullName "AAD"
#Get our list of certificates we'll request...

if($PAASOnly.IsPresent)
{
    $CertsToCreate+=$Constants.PaasCerts
}
else
{
    $CertsToCreate=$Constants.MandatoryCerts
    if($IsAdfs.IsPresent)
    {
        $OutputPath=Join-Path $CertificatePath.FullName "ADFS"
        $CertsToCreate+=$Constants.AdfsCerts
    }
    if($CreatePAAS.IsPresent)
    {
        $CertsToCreate+=$Constants.PaasCerts
    }
}

#PoshACME Azure Plugin Parameters
$AzParams=@{
    AZSubscriptionId=$SubscriptionId;
    AZTenantId=$TenantId;
    AZAppCred=$(New-Object PSCredential $ClientId,$(ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force))
}
$RootZone=[string]::Join('.',($ExternalFQDN.Split('.')|Select-Object -Last 2))
$SubDomain=$ExternalFQDN -replace ".$RootZone",''

#endregion

#region Azure Connection
Write-Information "Testing Connection To Azure..."
$TokenUriBld=New-Object System.UriBuilder('https://login.microsoftonline.com')
$TokenUriBld.Path="$TenantId/oauth2/token"
$RequestBody=@{
    'grant_type'='client_credentials';
    'client_id'=$ClientId;
    'client_secret'=$ClientSecret;
    'resource'='https://management.azure.com/'
}
$ArmToken=Invoke-RestMethod -Method Post -Uri $TokenUriBld.Uri -Body $RequestBody -ContentType "application/x-www-form-urlencoded" -UseBasicParsing
if($null -eq $ArmToken){
    throw "Unable to retrieve an access token for ARM!"
}
$ArmUriBld=New-Object System.UriBuilder('https://management.azure.com')
$ArmUriBld.Query="api-version=2018-03-01-preview"
$ArmHeaders=@{Accept='application/json';Authorization="Bearer $($ArmToken.'access_token')"}
#Find the existing DNS Zone via ARM
Write-Information "Locating DNS Zone $RootZone"
$ArmUriBld.Path = "subscriptions/$SubscriptionId/providers/Microsoft.Network/dnszones"
$dnsZones=@()
$zoneUrl = $ArmUriBld.Uri
do {
    try
    {
        $response = Invoke-RestMethod -Uri $zoneUrl -Headers $ArmHeaders -UseBasicParsing
    } catch { throw }
    # grab the public zones from the response
    $dnsZones += $response.value | Where-Object { $_.properties.zoneType -eq 'Public' }
    $zoneUrl=$response.nextLink
    
} while ($null -ne $zoneUrl)
$RootZoneId=$dnsZones|Where-Object Name -eq $RootZone|Select-Object -First 1 -ExpandProperty id
if([string]::IsNullOrEmpty($RootZoneId))
{
    throw "Unable to find the DNS Zone $RootZone"
}

#endregion

#region Deploy CAA records
Write-Information "Creating CAA Records in DNS Zone $RootZone"
$CaaNames=$CertsToCreate.value|ForEach-Object{"$($_.Replace('*.','')).$SubDomain"}|Select-Object -Unique
foreach ($CaaName in $CaaNames)
{
    $ArmUriBld.Path="$RootZoneId/CAA/$CaaName"
    #See if it's there already...
    $CaaRecord=$null
    Write-Information "Checking for existence of $($ArmUriBld.Path)"
    try{
        $CaaRecord=Invoke-RestMethod -Uri $ArmUriBld.Uri -Headers $ArmHeaders -UseBasicParsing
        Write-Information "CAA Record $CaaRecord already exists!"
    }catch{
        #It must not exist...
    }
    if ($null -eq $CaaRecord) {
        Write-Information "Creating new CAA Record $CaaName"
        $CaaProps=[pscustomobject]@{
            properties=@{
                TTL=3600;
                caaRecords=@(
                    @{"flags"= 0;"tag"="iodef";"value"="mailto:admin@stackpoc.com"},
                    @{"flags"= 0;"tag"= "issue";"value"="letsencrypt.org"}
                )
            }
        }
        $CaaRecord=Invoke-RestMethod -Uri $ArmUriBld.Uri -Method Put -Headers $ArmHeaders -Body $($CaaProps | ConvertTo-Json -Depth 5) -ContentType 'application/json' -ErrorAction Stop
        Write-Information "Created Record $($CaaRecord.id) successfully! Waiting 5 seconds..."
        Start-Sleep -Seconds 5
    }
}
#endregion

Write-Information "Creating Certificate Set for ${ExternalFQDN} Location: $($LEServer.location) Account:$($LEAccount.id) IsADFS:$($IsAdfs.IsPresent) -> ${OutputPath}"

#region Certificate Requests

#Create the certificate requests...
for ($i = 0; $i -lt $CertsToCreate.Length; $i++)
{ 
    #region Process Certificate

    $ActivityId=100+$i
    $PercentComplete=([double]($i+1)/[double]$CertsToCreate.Length * 100)
    $CertToCreate=$CertsToCreate[$i]
    
    $Subjects=@($CertToCreate.Value)
    $PrimarySubject=$Subjects|Select-Object -First 1
    $Subject="${PrimarySubject}.${ExternalFQDN}"
    $SubjectAltNames=@($Subjects|ForEach-Object{"dns=$_.${ExternalFQDN}"})
    $SanStrings=[string]::Join('&',$SubjectAltNames)
    $FileNameBase=$Subject.Replace(".","-").Replace("*","star")

    #Create the folder
    $CertOutputPath=New-Item -Path $OutputPath -Name $CertToCreate.Name -ItemType Directory -Force
    #Create an .inf for the signing request
    $InfFileName=Join-Path $CertOutputPath.FullName "${FileNameBase}-request.inf"
    $CsrFileName=Join-Path $CertOutputPath.FullName "${FileNameBase}-csr.req"
    $PfxFileName=Join-Path $CertOutputPath.FullName "${FileNameBase}.pfx"

    try
    {
        Write-Information "Creating certificate request for $Subject -> $InfFileName"
        Write-Progress -Id $ActivityId -Activity 'Creating Certificate' -PercentComplete $PercentComplete -Status "Creating certificate request for $Subject -> $InfFileName"
        
        $LECert=(Get-PACertificate -List|Where-Object Subject -eq $Subject|Select-Object -First 1)
        if($null -ne  $LECert)
        {
            #Request renewal of the cert LE and POSH-ACME will do the rest.
            Write-Information "Renewing Certificate $($LECert.Subject)"
        }
        
        #Generate the CSR...
        Write-Information "Creating CSR $CsrFileName"
        Write-Progress -ParentId $ActivityId -Activity 'Requesting Certificate' -PercentComplete 25 -Status "Creating CSR $CsrFileName"
        $Constants.RequestInf -f "CN=$Subject",$KeyLength,$HashAlgorithm,$SanStrings|Set-Content -Path $InfFileName -Force
        Start-Process -FilePath "certreq.exe" -ArgumentList "-new","-f","`"$InfFileName`"","`"$CsrFileName`"" -Wait
        
        #Request the Cert from LE
        Write-Information "Submitting CSR to Let's Encrypt"
        Write-Progress -ParentId $ActivityId -Activity 'Requesting Certificate'-PercentComplete 50 -Status "Submitting CSR to Let's Encrypt"
        $LECert=New-PACertificate -CSRPath $CsrFileName -AcceptTOS `
            -DnsPlugin Azure -PluginArgs $AzParams -DNSSleep 150 `
            -ValidationTimeout 150 -Verbose:($PSBoundParameters['Verbose'] -eq $true)
        
        #Import the result
        Write-Information "Importing Certificate $($LECert.FullChainFile)"
        Write-Progress -ParentId $ActivityId -Activity 'Requesting Certificate' -PercentComplete 75 -Status "Importing Certificate $($LECert.FullChainFile)"
        $NewCert=Import-Certificate -FilePath $LECert.FullChainFile -CertStoreLocation Cert:\LocalMachine\My
        
        #Export it
        Write-Information "Exporting Certificate $($NewCert.Thumbprint) -> ${PfxFileName}"
        Write-Progress -ParentId $ActivityId -Activity 'Requesting Certificate' -PercentComplete 90 -Status "Exporting Certificate $($NewCert.Thumbprint) -> ${PfxFileName}"
        #The resultant .PFX will be in the output pipeline
        $NewCert|Export-PfxCertificate -ChainOption BuildChain -Password $CertificatePassword -FilePath $PfxFileName
        
        Write-Information "Created certificate for ${Subject}"     
    }
    catch
    {
        Write-Warning "Something went wrong! $_"
    }
    finally
    {
        Write-Progress -ParentId $ActivityId -Activity 'Requesting Certificate' -Completed
        Write-Progress -Id $ActivityId -Activity 'Creating Certificate' -Completed   
    }

    #endregion
}

#endregion

Write-Information "All Done, don't forget to renew soon!"

#endregion

<#
    .SYNOPSIS
        Generates a new set of infrastructure (and optional PaaS) certificates
    .PARAMETER ExternalFQDN
        The region dns zone
    .PARAMETER CertificatePath
        The directory where the certificates will be created
    .PARAMETER CertificatePassword
        The password used to protect the new certificates
    .PARAMETER SubscriptionId
        The Azure SubscriptionId
    .PARAMETER ClientId
        The Service Principal secret identifier
    .PARAMETER ClientSecret
        The Service Principal secret
    .PARAMETER TenantId
        The AAD tenant for the Service Principal
    .PARAMETER KeyLength
        The key length to be used
    .PARAMETER HashAlgorithm
        The hash algorithm to be used
    .PARAMETER IsAdfs
        The identity model is 'disconnected' ADFS
    .PARAMETER CreatePAAS
        Create the additional service required certificates
    .PARAMETER LEServer
        The Posh-ACME server
    .PARAMETER LEAccount
        The Posh-ACME account instance
#>