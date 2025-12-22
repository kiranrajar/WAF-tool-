Write-Host "`n🎉 AEGIS Shield - Production WAF Summary" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════`n" -ForegroundColor Cyan

Write-Host "✅ CURRENT STATUS" -ForegroundColor Green
Write-Host "  • WAF Engine: RUNNING on port 3000" -ForegroundColor White
Write-Host "  • ML API: RUNNING on port 8000" -ForegroundColor White
Write-Host "  • Dashboard: http://localhost:3000/`n" -ForegroundColor White

Write-Host "🛡️  ACTIVE FEATURES" -ForegroundColor Yellow
Write-Host "  ✓ ML-Based Anomaly Detection" -ForegroundColor Green
Write-Host "  ✓ Signature-Based Attack Detection" -ForegroundColor Green
Write-Host "  ✓ GeoIP Country Tracking" -ForegroundColor Green
Write-Host "  ✓ Bot Detection (User-Agent)" -ForegroundColor Green
Write-Host "  ✓ IP Reputation System" -ForegroundColor Green
Write-Host "  ✓ Auto-Blacklisting" -ForegroundColor Green
Write-Host "  ✓ Real-time Logging" -ForegroundColor Green
Write-Host "  ✓ Professional Dashboard`n" -ForegroundColor Green

Write-Host "📊 LIVE STATISTICS" -ForegroundColor Yellow
try {
    $stats = Invoke-RestMethod -Uri "http://localhost:3000/api/stats" -ErrorAction Stop
    Write-Host "  • Total Requests: $($stats.total)" -ForegroundColor Cyan
    Write-Host "  • Blocked Attacks: $($stats.blocked)" -ForegroundColor Red
    Write-Host "  • Allowed Requests: $($stats.allowed)" -ForegroundColor Green
    Write-Host "  • Average Risk: $([math]::Round($stats.avgRisk * 100, 2))%" -ForegroundColor Yellow
    Write-Host "  • Active Bans: $($stats.blacklistCount)`n" -ForegroundColor Magenta
    
    if ($stats.threats) {
        Write-Host "🎯 THREAT BREAKDOWN" -ForegroundColor Yellow
        foreach ($threat in $stats.threats.PSObject.Properties) {
            Write-Host "  • $($threat.Name): $($threat.Value)" -ForegroundColor Red
        }
    }
}
catch {
    Write-Host "  ⚠ Could not fetch stats (WAF may not be running)" -ForegroundColor Yellow
}

Write-Host "`n🚀 QUICK ACTIONS" -ForegroundColor Yellow
Write-Host "  1. View Dashboard:" -ForegroundColor White
Write-Host "     Start-Process http://localhost:3000/`n" -ForegroundColor Gray

Write-Host "  2. Test Attack Detection:" -ForegroundColor White
Write-Host "     Invoke-WebRequest -Uri `"http://localhost:3000/test?sql=admin' OR 1=1`" -UseBasicParsing`n" -ForegroundColor Gray

Write-Host "  3. View Logs:" -ForegroundColor White
Write-Host "     Invoke-RestMethod -Uri http://localhost:3000/api/logs`n" -ForegroundColor Gray

Write-Host "  4. Check Health:" -ForegroundColor White
Write-Host "     Invoke-RestMethod -Uri http://localhost:3000/health`n" -ForegroundColor Gray

Write-Host "📚 DOCUMENTATION" -ForegroundColor Yellow
Write-Host "  • Full Guide: RUNNING.md" -ForegroundColor Cyan
Write-Host "  • Enterprise Setup: ENTERPRISE-DEPLOYMENT.md" -ForegroundColor Cyan
Write-Host "  • README: README.md`n" -ForegroundColor Cyan

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "🛡️  AEGIS Shield is protecting your applications!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════`n" -ForegroundColor Cyan
