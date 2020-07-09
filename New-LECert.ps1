#REQUIRES -RunAsAdministrator
#REQUIRES -Modules "PKI","Posh-ACME"

[CmdletBinding()]
param
(
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.IO.DirectoryInfo]$CertificatePath=(Get-Item $env:TEMP),
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
    #This is a dictionary of Name,Value Pairs
    [PSCustomObject[]]$CertificateToCreate,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
    [string]$ExternalFQDN,
    [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
    [ValidateSet(2048, 4096, 8192)]
    [int]$KeyLength = 2048,
    [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
    [ValidateSet('SHA256', 'SHA384', 'SHA512')]
    [string]$HashAlgorithm = 'SHA256',
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
    [string]$SubscriptionId,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
    [string]$ClientId,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
    [string]$ClientSecret,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
    [string]$TenantId,
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
    [SecureString]$CertificatePassword,
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [PSCustomObject]$LEAccount=(Get-PAAccount),
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [PSCustomObject]$LEServer=(Get-PAServer),
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [string]$AzureDnsApiVersion="2018-03-01-preview"
)

BEGIN
{
    $CertRequestTemplate=@{
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
    }

    #Parse the root domain and subdomain
    $RootZone=[string]::Join('.',($ExternalFQDN.Split('.')|Select-Object -Last 2))
    $SubDomain=$ExternalFQDN -replace ".$RootZone",''

    #PoshACME Azure Plugin Parameters
    $AzParams=@{
        AZSubscriptionId=$SubscriptionId;
        AZTenantId=$TenantId;
        AZAppCred=$(New-Object PSCredential $ClientId,$(ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force))
    }

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

    #Setup the ARM Client
    $ArmUriBld=New-Object System.UriBuilder('https://management.azure.com')
    $ArmUriBld.Query="api-version=$AzureDnsApiVersion"
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
}
PROCESS
{
    foreach ($CertToCreate in $CertificateToCreate) 
    {
        $ActivityId = 12333    
        $Subjects=@($CertToCreate.Value)
        $PrimarySubject=$Subjects|Select-Object -First 1
        $Subject="${PrimarySubject}.${ExternalFQDN}"
        $SubjectAltNames=@($Subjects|ForEach-Object{"dns=$_.${ExternalFQDN}"})
        $SanStrings=[string]::Join('&',$SubjectAltNames)
        $FileNameBase=$Subject.Replace(".","-").Replace("*","star")
    
        #Create the folder
        $CertOutputPath=New-Item -Path $CertificatePath -Name $CertToCreate.Name -ItemType Directory -Force
        #Create an .inf for the signing request
        $InfFileName=Join-Path $CertOutputPath.FullName "${FileNameBase}-request.inf"
        $CsrFileName=Join-Path $CertOutputPath.FullName "${FileNameBase}-csr.req"
        $PfxFileName=Join-Path $CertOutputPath.FullName "${FileNameBase}.pfx"


        #region Deploy CAA records
        Write-Information "Creating CAA Records in DNS Zone $RootZone"
        $CaaNames=$CertToCreate.value|ForEach-Object{"$($_.Replace('*.','')).$SubDomain"}|Select-Object -Unique
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


        $LECert=(Get-PACertificate -List|Where-Object Subject -eq $Subject|Select-Object -First 1)
        if($null -ne  $LECert)
        {
            #Request renewal of the cert LE and POSH-ACME will do the rest.
            Write-Information "Renewing Certificate $($LECert.Subject)"
            $LECert=Submit-Renewal -MainDomain $Subject -PluginArgs $AzParams
        }
        else
        {
            #Generate the CSR...
            Write-Information "Creating CSR $CsrFileName"
            Write-Progress -ParentId $ActivityId -Activity 'Requesting Certificate' -PercentComplete 25 -Status "Creating CSR $CsrFileName"
            $CertRequestTemplate.RequestInf -f "CN=$Subject",$KeyLength,$HashAlgorithm,$SanStrings|Set-Content -Path $InfFileName -Force
            Start-Process -FilePath "certreq.exe" -ArgumentList "-new","-f","`"$InfFileName`"","`"$CsrFileName`"" -Wait
            
            #Request the Cert from LE
            Write-Information "Submitting CSR to Let's Encrypt"
            Write-Progress -ParentId $ActivityId -Activity 'Requesting Certificate'-PercentComplete 50 -Status "Submitting CSR to Let's Encrypt"
            $LECert=New-PACertificate -CSRPath $CsrFileName -AcceptTOS `
                -DnsPlugin Azure -PluginArgs $AzParams -DNSSleep 150 `
                -ValidationTimeout 150 -Verbose:($PSBoundParameters['Verbose'] -eq $true)            
        }
        
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
}
END
{

}
