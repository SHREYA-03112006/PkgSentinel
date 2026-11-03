# PkgSentinel — Windows Developer Setup Script
Write-Host "[+] Initializing PkgSentinel Development Environment..." -ForegroundColor Cyan

if (-not (Test-Path ".env")) {
    Write-Host "[*] Copying .env.example to .env..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
}

# Python virtual environment
Write-Host "[*] Checking Python environment..." -ForegroundColor Yellow
Set-Location security-engine
python -m pip install -e ".[dev]"
Set-Location ..

# Frontend
Write-Host "[*] Checking Frontend dependencies..." -ForegroundColor Yellow
Set-Location frontend
npm.cmd install
Set-Location ..

Write-Host "[✓] Setup complete! You can start services via Docker Compose or locally." -ForegroundColor Green

