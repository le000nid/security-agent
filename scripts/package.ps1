$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
try {
    $version = '0.4.0'
    $headVersion = & git show HEAD:app/__init__.py
    if ($LASTEXITCODE -ne 0 -or ($headVersion -join "`n") -notmatch '__version__ = "0\.4\.0"') { throw 'Commit the reviewed v0.4.0 release first. Packaging uses committed HEAD only.' }
    & git diff --quiet HEAD -- .
    if ($LASTEXITCODE -ne 0) { throw 'Commit reviewed tracked changes before packaging. Untracked files are never included.' }
    $tracked = @(& git ls-tree -r --name-only HEAD)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read committed files.' }
    foreach ($name in $tracked) {
        if ($name -ne '.env.example' -and $name -match '(^|/)(\.env($|\.)|id_rsa$|id_ed25519$)|\.(pem|key)$') { throw 'Potential secret file tracked in HEAD; remove it before packaging.' }
    }
    New-Item -ItemType Directory -Force -Path 'dist' | Out-Null
    $output = Join-Path (Get-Location) "dist/security-agent-v$version.zip"
    if (Test-Path -LiteralPath $output) { throw 'Release archive already exists; move it before packaging again.' }
    & git archive --format=zip --output=$output HEAD
    if ($LASTEXITCODE -ne 0) { throw 'git archive failed.' }
    Write-Host "Created $output from committed HEAD. No untracked files or local runtime artifacts included."
} catch { Write-Error $_.Exception.Message -ErrorAction Continue; exit 6 }
