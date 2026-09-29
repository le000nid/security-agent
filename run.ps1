$Forwarded = @($args)
. "$PSScriptRoot/scripts/common.ps1"
try {
    Test-Docker
    New-RuntimeDirectories
    $mode = 'agent'
    if ($Forwarded.Count -gt 0) {
        $mode = $Forwarded[0]
        $Forwarded = @($Forwarded | Select-Object -Skip 1)
    }
    if ($mode -notin @('agent', 'scan', 'deterministic', 'doctor', 'latest')) { throw 'Use agent, scan, deterministic, doctor, or latest.' }
    $defaults = @()
    if ($mode -notin @('doctor', 'latest')) {
        Start-Lab
        if (-not ($Forwarded | Where-Object { $_ -eq '--target-url' -or $_ -like '--target-url=*' })) {
            $defaults += @('--target-url', 'http://juice-shop:3000')
        }
        if (-not ($Forwarded | Where-Object { $_ -eq '--source-path' -or $_ -like '--source-path=*' })) {
            $defaults += @('--source-path', '/targets/sample-app')
        }
    }
    & docker compose --profile agent run --rm --no-deps agent $mode @defaults @Forwarded
    exit $LASTEXITCODE
} catch { Write-Error $_.Exception.Message -ErrorAction Continue; exit 6 }
