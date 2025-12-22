Write-Host "`n🛡️  Starting AEGIS Shield Ecosystem..." -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════`n" -ForegroundColor Cyan

# 1. Start ML API
Write-Host "🚀 Starting ML API (Python)..." -ForegroundColor Yellow
Start-Process python -ArgumentList "ml/api.py" -NoNewWindow
Start-Sleep -Seconds 2

# 2. Start Target Application
Write-Host "🎯 Starting Target Application (Node)..." -ForegroundColor Yellow
Start-Process node -ArgumentList "backend/target-app.js" -NoNewWindow
Start-Sleep -Seconds 2

# 3. Start WAF Proxy
Write-Host "🛡️  Starting AEGIS WAF Proxy (Node)..." -ForegroundColor Yellow
Start-Process node -ArgumentList "backend/waf-enhanced.js" -NoNewWindow
Start-Sleep -Seconds 3

Write-Host "`n✅ All systems online!" -ForegroundColor Green
Write-Host "📊 Dashboard: http://localhost:3000/dashboard" -ForegroundColor Gray
Write-Host "🎯 App Proxy: http://localhost:3000/" -ForegroundColor Gray
Write-Host "══════════════════════════════════════════`n" -ForegroundColor Cyan

./status.ps1
