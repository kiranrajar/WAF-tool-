param (
    [string]$TargetUrl = "https://waf-visual-project.vercel.app"
)

Write-Host "`n🛡️  Testing Live WAF at: $TargetUrl" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════`n" -ForegroundColor Cyan

# 1. Normal Request (Should Proxy)
Write-Host "1. Testing Normal Request..." -ForegroundColor Yellow
try {
    $res = Invoke-WebRequest -Uri "$TargetUrl" -UseBasicParsing -ErrorAction Stop
    if ($res.StatusCode -eq 200) {
        Write-Host "✅ Allowed (200 OK)" -ForegroundColor Green
        # Simple check if it looks like the bookstore
        if ($res.Content -like "*Books to Scrape*") {
            Write-Host "   -> Content confirmed: Books to Scrape" -ForegroundColor Gray
        }
        else {
            Write-Host "   -> Warning: Content does not look like bookstore" -ForegroundColor Magenta
        }
    }
    else {
        Write-Host "❌ Failed with status $($res.StatusCode)" -ForegroundColor Red
    }
}
catch {
    Write-Host "❌ Request Failed: $_" -ForegroundColor Red
}

# 2. SQL Injection (Should Block)
Write-Host "`n2. Testing SQL Injection..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "$TargetUrl/?q=UNION SELECT password" -UseBasicParsing -ErrorAction Stop | Out-Null
    Write-Host "❌ FAILED: Attack was ALLOWED" -ForegroundColor Red
}
catch {
    if ($_.Exception.Response.StatusCode -eq 403) {
        Write-Host "✅ BLOCKED (403 Forbidden)" -ForegroundColor Green
    }
    else {
        Write-Host "⚠️  Blocked with unexpected status: $($_.Exception.Response.StatusCode)" -ForegroundColor Yellow
    }
}

# 3. XSS (Should Block)
Write-Host "`n3. Testing XSS..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "$TargetUrl/?search=<script>alert(1)</script>" -UseBasicParsing -ErrorAction Stop | Out-Null
    Write-Host "❌ FAILED: Attack was ALLOWED" -ForegroundColor Red
}
catch {
    if ($_.Exception.Response.StatusCode -eq 403) {
        Write-Host "✅ BLOCKED (403 Forbidden)" -ForegroundColor Green
    }
    else {
        Write-Host "⚠️  Blocked with unexpected status: $($_.Exception.Response.StatusCode)" -ForegroundColor Yellow
    }
}

# 4. Check Dashboard
Write-Host "`n4. Checking Dashboard..." -ForegroundColor Yellow
try {
    $res = Invoke-WebRequest -Uri "$TargetUrl/dashboard/index.html" -UseBasicParsing -ErrorAction Stop
    if ($res.StatusCode -eq 200) {
        Write-Host "✅ Dashboard Accessible" -ForegroundColor Green
    }
}
catch {
    Write-Host "❌ Dashboard Inaccessible" -ForegroundColor Red
}

Write-Host "`n══════════════════════════════════════════" -ForegroundColor Cyan
