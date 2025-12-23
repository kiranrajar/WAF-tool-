$Uri = "mongodb+srv://Kiranrajar:<db_password>@cluster0.yumabsi.mongodb.net/?appName=Cluster0"

Write-Host "`n[INFO] MongoDB Setup for Vercel and Local" -ForegroundColor Cyan
$Password = Read-Host "Please enter your MongoDB Password (for user 'Kiranrajar')"

if ([string]::IsNullOrWhiteSpace($Password)) {
    Write-Host "[ERROR] Password cannot be empty." -ForegroundColor Red
    exit
}

$FinalUri = $Uri.Replace("<db_password>", $Password)

# 1. Update Local .env
$EnvContent = "MONGODB_URI=$FinalUri"
Set-Content -Path "backend/.env" -Value $EnvContent
Write-Host "[SUCCESS] Saved to backend/.env (for local testing)" -ForegroundColor Green

# 2. Add to Vercel
Write-Host "[INFO] Attempting to add to Vercel Environment..." -ForegroundColor Yellow

# Try to add env var using process input redirection which is safer than pipe in some PS versions
$pInfo = New-Object System.Diagnostics.ProcessStartInfo
$pInfo.FileName = "vercel"
$pInfo.Arguments = "env add MONGODB_URI production"
$pInfo.RedirectStandardInput = $true
$pInfo.UseShellExecute = $false
$p = [System.Diagnostics.Process]::Start($pInfo)
$p.StandardInput.WriteLine($FinalUri)
$p.StandardInput.Close()
$p.WaitForExit()

Write-Host "`n[INFO] If the above failed, run this manually:" -ForegroundColor Cyan
Write-Host "vercel env add MONGODB_URI production" -ForegroundColor White
Write-Host "(and paste this value: $FinalUri)" -ForegroundColor White

Write-Host "`n[INFO] Redeploying..." -ForegroundColor Yellow
vercel --prod
