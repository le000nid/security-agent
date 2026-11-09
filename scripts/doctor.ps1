$DoctorArgs = @($args)
. "$PSScriptRoot/common.ps1"
try {
    Test-Docker
    if (-not (Test-Path -LiteralPath '.env')) { Write-Warning '.env missing. Run .\scripts\bootstrap.ps1' }
    if (-not (Test-Path -LiteralPath 'targets/sample-app')) { throw 'Sample target missing; restore repository fixtures.' }
    New-RuntimeDirectories
    Invoke-Docker compose images agent
    $config = (& docker compose --profile agent config --format json | ConvertFrom-Json)
    Invoke-Docker image inspect $config.services.agent.image --format '{{.Os}}/{{.Architecture}}'
    Invoke-Docker compose ps -a juice-shop
    Invoke-Docker compose --profile agent run --rm --no-deps agent doctor @DoctorArgs
} catch { Write-Error $_.Exception.Message -ErrorAction Continue; exit 6 }
