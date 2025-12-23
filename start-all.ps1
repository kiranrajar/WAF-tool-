Write-Host "Starting AEGIS Shield Ecosystem..." -ForegroundColor Cyan

# 1. Start ML API
Write-Host "Starting ML API..."
Start-Process python -ArgumentList "ml/api.py" -NoNewWindow
Start-Sleep -Seconds 2

# 2. Start Target Application
Write-Host "Starting Target App..."
Start-Process node -ArgumentList "backend/target-app.js" -NoNewWindow
Start-Sleep -Seconds 2

# 3. Start WAF Proxy
Write-Host "Starting WAF Proxy..."
Start-Process node -ArgumentList "backend/waf-enhanced.js" -NoNewWindow
Start-Sleep -Seconds 3

Write-Host "All systems online!" -ForegroundColor Green
Write-Host "Dashboard: http://localhost:3000/dashboard"
Write-Host "Target: http://localhost:3000/"
