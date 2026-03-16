@echo off
echo.
echo   ⚔  VulnSamurai
echo ======================================

echo [1/2] Building image (first time ~15 min)...
docker build -t vulnsamurai .
if %errorlevel% neq 0 (
    echo ERROR: Docker build failed. Is Docker Desktop running?
    pause
    exit /b 1
)

echo [2/2] Starting container...
docker rm -f vulnsamurai 2>nul
docker run -d ^
  --name vulnsamurai ^
  --env-file .env ^
  -p 3000:3000 ^
  -v vulnsamurai_data:/data ^
  vulnsamurai

if %errorlevel% neq 0 (
    echo ERROR: Failed to start container.
    pause
    exit /b 1
)

echo.
echo ======================================
echo   Ready at http://localhost:3000
echo   Logs: docker logs -f vulnsamurai
echo ======================================
echo.
pause
