[CmdletBinding()]
param
(
    [Parameter()]
    [string]$ImageBase='servercore-ltsc2019'
)
$ErrorActionPreference='Stop'

. "$PSScriptRoot\build.config.ps1"

$STAMP_VERSION=$env:DOCKER_APPLICATION_VERSION
$imageFullName = ("{0}/{1}:{2}-{3}" -f $env:DOCKER_REPO, $env:DOCKER_IMAGE, $STAMP_VERSION,$ImageBase)
$imageLatestName = ("{0}/{1}:latest" -f $env:DOCKER_REPO, $env:DOCKER_IMAGE)

Write-Host `Pushing $imageFullName`
docker push $imageFullName

Write-Host `Pushing $imageLatestName`
docker push $imageLatestName
