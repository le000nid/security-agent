$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $ProjectRoot
function Invoke-Docker {
    & docker @args
    if ($LASTEXITCODE -ne 0) { throw 'Docker command failed. See docs/TROUBLESHOOTING.md.' }
}
function Test-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker not found. Install Docker Desktop first.' }
    Invoke-Docker info --format '{{.OSType}}/{{.Architecture}}'
    $engine = & docker info --format '{{.OSType}}'
    if ($engine -ne 'linux') { throw 'Start Docker Desktop and select Linux containers.' }
    Invoke-Docker compose version
    Write-Host "Host architecture: $env:PROCESSOR_ARCHITECTURE"
    Invoke-Docker compose config --quiet
}
function New-RuntimeDirectories {
    foreach ($dir in @('runs', 'logs', 'reports')) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
}
function Initialize-AgentImage {
    $images = @(& docker compose --profile agent config --images agent)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve Compose images.' }
    $selected = $images | Select-Object -First 1
    if ($selected -like 'ai-security-agent:*') { Invoke-Docker compose build agent }
    else { Invoke-Docker compose --profile agent pull agent }
}
function Start-Lab {
    Invoke-Docker compose up -d --wait --wait-timeout 180 juice-shop demo-full
}
