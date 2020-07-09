# Indicates that the windowsservercore image will be used as the base image.
FROM mcr.microsoft.com/windows/servercore:ltsc2019
#Stack PowerShell DockerFile
ARG STAMPVERSION=1901
ARG NUGETVERSION=2.8.5.201
# Metadata indicating an image maintainer.
LABEL maintainer="chris.speers@avanade.com"

RUN echo Azure Stack Powershell %STAMPVERSION% > c:\image.txt
#Our shared volume to exchange files
RUN md C:\Users\ContainerAdministrator\AppData\Local\Posh-ACME
RUN md C:\Stack
RUN md C:\tools
RUN md C:\temp

#Add the Azure Stack tools
ADD https://github.com/Azure/AzureStack-Tools/archive/master.zip C:/temp/master.zip
RUN powershell -Command \
    Write-Host 'Expanding Azure Stack Tools...'; \
    Expand-Archive -Path C:\temp\master.zip -DestinationPath C:\tools;

#Patch up the Connect Module to work in here
RUN powershell -Command \
    Write-Host "Patching up AzureStack.Connect.psm1"; \
    $fileContent=Get-Content -Path C:\tools\AzureStack-Tools-master\Connect\AzureStack.Connect.psm1; \
    $fileContent=$fileContent.Replace(', VpnClient','').Replace(',VpnClient',''); \
    Set-Content -Value $fileContent -Path C:\tools\AzureStack-Tools-master\Connect\AzureStack.Connect.psm1 -Force;

#Copy the login helper
COPY LoginToStack.ps1 /tools
#Copy the LE helper
COPY New-LetsEncryptStackCerts.ps1 /tools

#Azure RM CMDLETS
RUN powershell -Command \
    Write-Host "Setting Up OneGet..."; \
    Install-PackageProvider -Name NuGet -MinimumVersion %NUGETVERSION% -Force; \
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; \
    Write-Host "Installing AzureRM for %STAMPVERSION%"; \
    if ("%STAMPVERSION%" -eq "1810") { \
        Install-Module -Name AzureRm.BootStrapper -Force; \
        Use-AzureRmProfile -Profile 2018-03-01-hybrid -Force; \
    } \
    elseif("%STAMPVERSION%" -eq "1811") { \
        Install-Module -Name AzureRm.BootStrapper -Force; \
        Use-AzureRmProfile -Profile 2018-03-01-hybrid -Force; \
    } \
    elseif("%STAMPVERSION%" -gt "1901" -and "%STAMPVERSION%" -lt "1904") { \
        Install-Module -Name AzureRm -RequiredVersion 2.4.0 -Force; \
    } \
    elseif("%STAMPVERSION%" -ge "1904" -and "%STAMPVERSION%" -le "1908") { \
        Install-Module -Name AzureRm.BootStrapper -Force; \
        Use-AzureRmProfile -Profile 2019-03-01-hybrid -Force; \
    } \
    elseif("%STAMPVERSION%" -ge "1910") { \
        Install-Module -Name AzureRm.BootStrapper -Force; \
        Use-AzureRmProfile -Profile 2019-03-01-hybrid -Force; \
    }
#AzureStack Module
RUN powershell -Command \
    Write-Host "Installing Azure Stack Module for %STAMPVERSION%"; \
    if ("%STAMPVERSION%" -eq "1810") { \
        Install-Module -Name AzureStack -RequiredVersion 1.5.0 -Force; \
    } \
    elseif("%STAMPVERSION%" -eq "1811") { \
        Install-Module -Name AzureStack -RequiredVersion 1.6.0 -Force; \
    } \
    elseif("%STAMPVERSION%" -gt "1901" -and "%STAMPVERSION%" -lt "1904") { \
        Install-Module -Name AzureStack -RequiredVersion 1.7.1 -Force; \
    } \
    elseif("%STAMPVERSION%" -ge "1904" -and "%STAMPVERSION%" -le "1908") { \
        Install-Module -Name AzureStack -RequiredVersion 1.7.2 -Force; \
    } \
    elseif("%STAMPVERSION%" -le "1910") { \
        Install-Module -Name AzureStack -RequiredVersion 1.8.0 -Force \
    } \
    elseif("%STAMPVERSION%" -ge "2002") { \
        Install-Module -Name AzureStack -RequiredVersion 1.8.1 -Force \
    }

#Enhanced Storage CMDLETS
RUN powershell -Command \
    Write-Host "Enabling 'Extra' Storage Features"; \
    Install-Module -Name Azure.Storage -RequiredVersion 4.5.0 -Force -AllowClobber; \
    Install-Module -Name AzureRM.Storage -RequiredVersion 5.0.4 -Force -AllowClobber; \
    Uninstall-Module Azure.Storage -RequiredVersion 4.6.1 -Force;

#Posh-ACME Module
RUN powershell -Command \
    Write-Host "Installing POSH-ACME Module"; \
    Install-Module Posh-ACME -Force;

#Clean up
RUN rd C:\temp /q /s
#Set a volume for the working directory
VOLUME [ "C:/Stack" ]
#Set a volume for the profiles
VOLUME [ "C:/Users/ContainerAdministrator/AppData/Roaming/Windows Azure Powershell" ]
#Set a volume for the POSH-ACME data
VOLUME [ "C:/Users/ContainerAdministrator/AppData/Local/Posh-ACME" ]
#Setup the powershell profile
RUN echo . C:\Tools\LoginToStack.ps1 -StartPath C:\Stack >> C:\Users\ContainerAdministrator\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1

# Sets a command or process that will run each time a container is run from the new image.
ENV Azure_Profile_Autosave="true"
ENV Azure_Stack_Version=${STAMPVERSION}
CMD [ "powershell"]