[CmdletBinding()]
param
(
    [Parameter()]
    [string]$ImageBase='servercore-ltsc2019',
    [Parameter()]
    [switch]$TagLatest
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\build.config.ps1"
$STAMP_VERSION=$env:DOCKER_APPLICATION_VERSION
$imageFullName = ("{0}/{1}:{2}-{3}" -f $env:DOCKER_REPO, $env:DOCKER_IMAGE, $STAMP_VERSION,$ImageBase)
$imageLatestName = ("{0}/{1}:latest" -f $env:DOCKER_REPO, $env:DOCKER_IMAGE)

Write-Host `Building $imageFullName`
Start-Process "docker.exe" `
    -ArgumentList 'build',"--build-arg STAMPVERSION=$STAMP_VERSION",'.','-t',$imageFullName `
    -NoNewWindow -Wait
if($TagLatest) {
    Write-Host "Tagging image as latest"
    Start-Process "docker.exe" -ArgumentList 'tag',$imageFullName,$imageLatestName -NoNewWindow -Wait
}
