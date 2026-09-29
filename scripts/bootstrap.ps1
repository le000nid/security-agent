. "$PSScriptRoot/common.ps1"
try {
    if (-not (Test-Path -LiteralPath '.env')) { Copy-Item -LiteralPath '.env.example' -Destination '.env' }
    New-RuntimeDirectories
    Test-Docker
    Initialize-AgentImage
    Start-Lab
    Invoke-Docker compose --profile agent run --rm agent scan --mode full --target-url http://juice-shop:3000 --source-path /targets/sample-app --no-llm
    Write-Host 'Bootstrap complete. Set LLM_API_KEY in .env, then run .\scripts\doctor.ps1 and .\run.ps1 agent'
} catch { Write-Error $_.Exception.Message -ErrorAction Continue; exit 6 }
