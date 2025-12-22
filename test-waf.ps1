Write-Host "`n🛡️  AEGIS Shield - Production WAF Test Suite" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════`n" -ForegroundColor Cyan

# Test 1: Health Check
Write-Host "Test 1: Health Check..." -ForegroundColor Yellow
$health = Invoke-RestMethod -Uri "http://localhost:3000/health"
Write-Host "✓ Status: $($health.status)" -ForegroundColor Green
Write-Host "✓ Version: $($health.version)" -ForegroundColor Green
Write-Host "✓ Uptime: $([math]::Round($health.uptime, 2))s`n" -ForegroundColor Green

# Test 2: Normal Requests
Write-Host "Test 2: Sending Normal Requests..." -ForegroundColor Yellow
$normalEndpoints = @('/home', '/about', '/products', '/contact')
foreach ($endpoint in $normalEndpoints) {
    try {
        Invoke-WebRequest -Uri "http://localhost:3000$endpoint" -UseBasicParsing -ErrorAction Stop | Out-Null
        Write-Host "✓ Normal request to $endpoint - Allowed" -ForegroundColor Green
    } catch {
        Write-Host "✗ Request failed: $_" -ForegroundColor Red
    }
}
Write-Host ""

# Test 3: SQL Injection Attacks
Write-Host "Test 3: Testing SQL Injection Detection..." -ForegroundColor Yellow
$sqlAttacks = @(
    "/login?user=admin' OR 1=1--",
    "/search?id=1'; DROP TABLE users;--",
    "/api/data?filter=1 UNION SELECT password FROM users"
)
foreach ($attack in $sqlAttacks) {
    try {
        Invoke-WebRequest -Uri "http://localhost:3000$attack" -UseBasicParsing -ErrorAction Stop | Out-Null
        Write-Host "✗ SQLi attack NOT blocked: $attack" -ForegroundColor Red
    } catch {
        Write-Host "✓ SQLi attack BLOCKED: $attack" -ForegroundColor Green
    }
}
Write-Host ""

# Test 4: XSS Attacks
Write-Host "Test 4: Testing XSS Detection..." -ForegroundColor Yellow
$xssAttacks = @(
    "/search?q=<script>alert(1)</script>",
    "/comment?text=<img src=x onerror=alert(1)>",
    "/profile?bio=javascript:alert(document.cookie)"
)
foreach ($attack in $xssAttacks) {
    try {
        Invoke-WebRequest -Uri "http://localhost:3000$attack" -UseBasicParsing -ErrorAction Stop | Out-Null
        Write-Host "✗ XSS attack NOT blocked: $attack" -ForegroundColor Red
    } catch {
        Write-Host "✓ XSS attack BLOCKED: $attack" -ForegroundColor Green
    }
}
Write-Host ""

# Test 5: Path Traversal
Write-Host "Test 5: Testing Path Traversal Detection..." -ForegroundColor Yellow
$pathAttacks = @(
    "/file?path=../../etc/passwd",
    "/download?file=../../../windows/system32/config/sam"
)
foreach ($attack in $pathAttacks) {
    try {
        Invoke-WebRequest -Uri "http://localhost:3000$attack" -UseBasicParsing -ErrorAction Stop | Out-Null
        Write-Host "✗ Path Traversal NOT blocked: $attack" -ForegroundColor Red
    } catch {
        Write-Host "✓ Path Traversal BLOCKED: $attack" -ForegroundColor Green
    }
}
Write-Host ""

# Test 6: Statistics
Write-Host "Test 6: Fetching Statistics..." -ForegroundColor Yellow
$stats = Invoke-RestMethod -Uri "http://localhost:3000/api/stats"
Write-Host "✓ Total Requests: $($stats.total)" -ForegroundColor Green
Write-Host "✓ Blocked Attacks: $($stats.blocked)" -ForegroundColor Green
Write-Host "✓ Allowed Requests: $($stats.allowed)" -ForegroundColor Green
Write-Host "✓ Average Risk Score: $([math]::Round($stats.avgRisk * 100, 2))%" -ForegroundColor Green
Write-Host "✓ Active Blacklist: $($stats.blacklistCount) IPs`n" -ForegroundColor Green

# Test 7: Threat Breakdown
Write-Host "Test 7: Threat Type Breakdown..." -ForegroundColor Yellow
if ($stats.threats) {
    foreach ($threat in $stats.threats.PSObject.Properties) {
        Write-Host "  • $($threat.Name): $($threat.Value)" -ForegroundColor Cyan
    }
} else {
    Write-Host "  No threats detected yet" -ForegroundColor Gray
}
Write-Host ""

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "🎉 Test Suite Complete!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════`n" -ForegroundColor Cyan

Write-Host "📊 Dashboard: http://localhost:3000/" -ForegroundColor Yellow
Write-Host "🏥 Health: http://localhost:3000/health" -ForegroundColor Yellow
Write-Host "📈 Stats API: http://localhost:3000/api/stats`n" -ForegroundColor Yellow
