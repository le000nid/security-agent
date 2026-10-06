. "$PSScriptRoot/common.ps1"
try {
    if (-not (Test-Path -LiteralPath '.env')) { Copy-Item -LiteralPath '.env.example' -Destination '.env' }
    New-RuntimeDirectories
    Test-Docker
    Initialize-AgentImage
    Start-Lab
    foreach ($benchmark in @('sample-sast', 'juice-shop', 'demo-full')) {
        Invoke-Docker compose --profile agent run --rm --no-deps agent scan --benchmark $benchmark --no-llm
    }
    Write-Host 'Bootstrap complete. Run .\scripts\doctor.ps1 and .\run.ps1 ui. LLM is optional.'
} catch { Write-Error $_.Exception.Message -ErrorAction Continue; exit 6 }
