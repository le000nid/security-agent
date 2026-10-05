$Forwarded = @($args)
. "$PSScriptRoot/scripts/common.ps1"
try {
    Test-Docker
    New-RuntimeDirectories
    $command = 'agent'
    if ($Forwarded.Count -gt 0) {
        $command = $Forwarded[0]
        $Forwarded = @($Forwarded | Select-Object -Skip 1)
    }
    if ($command -notin @('agent', 'scan', 'deterministic', 'doctor', 'latest', 'ui', 'benchmarks')) { throw 'Use agent, scan, deterministic, doctor, latest, ui, or benchmarks.' }
    if ($command -eq 'ui') {
        Start-Lab
        Invoke-Docker compose --profile ui up -d --wait --wait-timeout 180 ui
        Write-Host 'AI Security Agent UI: http://127.0.0.1:8080'
        exit 0
    }
    $defaults = @()
    if ($command -in @('agent', 'scan', 'deterministic')) {
        $scope = ''; $benchmark = ''; $hasTarget = $false; $hasSource = $false
        for ($i = 0; $i -lt $Forwarded.Count; $i++) {
            $arg = $Forwarded[$i]
            if ($arg -eq '--mode' -and $i + 1 -lt $Forwarded.Count) { $scope = $Forwarded[$i + 1] }
            elseif ($arg -like '--mode=*') { $scope = $arg.Substring(7) }
            elseif ($arg -eq '--benchmark' -and $i + 1 -lt $Forwarded.Count) { $benchmark = $Forwarded[$i + 1] }
            elseif ($arg -like '--benchmark=*') { $benchmark = $arg.Substring(12) }
            elseif ($arg -eq '--target-url' -or $arg -like '--target-url=*') { $hasTarget = $true }
            elseif ($arg -eq '--source-path' -or $arg -like '--source-path=*') { $hasSource = $true }
        }
        if (-not $scope) {
            $scope = if ($benchmark -eq 'sample-sast' -or ($hasSource -and -not $hasTarget -and -not $benchmark)) { 'sast' } elseif ($benchmark -eq 'juice-shop' -or ($hasTarget -and -not $hasSource -and -not $benchmark)) { 'dast' } else { 'full' }
        }
        if ($scope -ne 'sast') { Start-Lab }
        if (-not $benchmark) {
            if ($scope -in @('dast', 'full') -and -not $hasTarget) { $defaults += @('--target-url', 'http://juice-shop:3000') }
            if ($scope -in @('sast', 'full') -and -not $hasSource) { $defaults += @('--source-path', '/targets/sample-app') }
        }
    }
    & docker compose --profile agent run --rm --no-deps agent $command @defaults @Forwarded
    exit $LASTEXITCODE
} catch { Write-Error $_.Exception.Message -ErrorAction Continue; exit 6 }
