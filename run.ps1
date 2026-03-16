# VulnSamurai — Windows PowerShell launcher
# Run with: Right-click → Run with PowerShell
# Or from terminal: .\run.ps1

Write-Host ""
Write-Host "  ⚔  VulnSamurai" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

# Auto-generate JWT secret and write into .env
$jwt = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
$envContent = Get-Content .env -Raw
$envContent = $envContent -replace 'changeme_run_openssl_rand_hex_64_and_paste_here', $jwt
Set-Content .env $envContent
Write-Host "[0/2] JWT secret generated." -ForegroundColor Green

# Build
Write-Host "[1/2] Building image (first time ~15 min)..." -ForegroundColor Yellow
docker build -t vulnsamurai .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Build failed. Is Docker Desktop running?" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Run
Write-Host "[2/2] Starting container..." -ForegroundColor Yellow
docker rm -f vulnsamurai 2>$null
docker run -d `
    --name vulnsamurai `
    --env-file .env `
    -p 3000:3000 `
    -v vulnsamurai_data:/data `
    vulnsamurai

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to start." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Green
Write-Host "  Ready at http://localhost:3000" -ForegroundColor Green
Write-Host "  Logs: docker logs -f vulnsamurai" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
Write-Host ""

# Open browser automatically
Start-Process "http://localhost:3000"
Read-Host "Press Enter to exit"
