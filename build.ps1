[CmdletBinding()]
param
(
    [Parameter()]
    [string]$ImageBase,
    [Parameter()]
    [switch]$TagLatest
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\build.config.ps1"
if([String]::IsNullOrEmpty($ImageBase)){
    $ImageBase=$env:BASE_IMAGE
    if([String]::IsNullOrEmpty($ImageBase)){
        $ImageBase='mcr.microsoft.com/windows/servercore:ltsc2019'
    }
}
$imageFullName = ("{0}/{1}:{2}" -f $env:DOCKER_REPO, $env:DOCKER_IMAGE,$env:DOCKER_APPLICATION_VERSION)
$imageLatestName = ("{0}/{1}:latest" -f $env:DOCKER_REPO, $env:DOCKER_IMAGE)


Write-Host `Building $imageFullName`
Start-Process "docker.exe" `
    -ArgumentList 'build',"--build-arg BASE_IMAGE=$ImageBase",'-t',$imageFullName, `
        '.' -NoNewWindow -Wait
if($TagLatest) {
    Write-Host "Tagging image as latest"
    Start-Process "docker.exe" -ArgumentList 'tag',$imageFullName,$imageLatestName -NoNewWindow -Wait
}