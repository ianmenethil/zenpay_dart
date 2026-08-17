<#
.SYNOPSIS
    Start the ZenPay reference backend and smoke-test its HTTP API.

.DESCRIPTION
    Prompts for PUBLIC_BASE_URL in example/.env, starts the server, waits until
    /api/v1/health responds, then creates and looks up a checkout session.
    The server stays running afterwards so a real/sandbox payment can still
    POST /api/v1/callbacks. Press Ctrl+C to stop.

.PARAMETER TestOnly
    Skip starting the server; hit an already-running instance (the old test.ps1).

.PARAMETER SkipTest
    Start the server without creating a checkout session (the old run.ps1).
#>
[CmdletBinding()]
param(
    [string]$EnvFilePath,
    [string]$PublicBaseUrl,
    [string]$BaseUrl,
    [string]$BearerToken,
    [string]$CustomerEmail = "test@example.com",
    [double]$PaymentAmount = 25.50,
    [switch]$OpenCheckoutUrl,
    [switch]$TestOnly,
    [switch]$SkipTest
)

$ErrorActionPreference = "Stop"

if ($TestOnly -and $SkipTest) {
    Write-Error "Use either -TestOnly or -SkipTest, not both."
    exit 1
}

function Invoke-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Host ""
    Write-Host "--- $Name ---" -ForegroundColor Cyan
    try {
        $result = & $Action
        Write-Host ($result | ConvertTo-Json -Depth 10) -ForegroundColor Green
        return $result
    } catch {
        Write-Host "FAILED" -ForegroundColor Red
        if ($_.ErrorDetails.Message) {
            Write-Host $_.ErrorDetails.Message -ForegroundColor Red
        } else {
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
        throw
    }
}

function Resolve-EnvFilePath {
    param([string]$ExplicitPath)
    if ($ExplicitPath) {
        return $ExplicitPath
    }
    $scriptDir = $PSScriptRoot
    if (Test-Path (Join-Path $scriptDir "example/.env")) {
        return Join-Path $scriptDir "example/.env"
    }
    if (Test-Path (Join-Path $scriptDir ".env")) {
        return Join-Path $scriptDir ".env"
    }
    return "example/.env"
}

function Get-EnvValue {
    param([string]$Content, [string]$Name)
    if ($Content -match "(?m)^$Name\s*=\s*(.*)$") {
        return $Matches[1].Trim()
    }
    return ""
}

function Update-PublicBaseUrl {
    param([string]$Path, [string]$RequestedUrl)

    $resolved = Resolve-Path $Path -ErrorAction SilentlyContinue
    if (-not $resolved -or -not (Test-Path $resolved)) {
        Write-Error "Could not find .env file at example/.env"
        exit 1
    }
    $Path = [string]$resolved
    $envContent = Get-Content $Path -Raw
    $currentUrl = Get-EnvValue -Content $envContent -Name "PUBLIC_BASE_URL"

    Write-Host ""
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    Write-Host "Current PUBLIC_BASE_URL: $currentUrl" -ForegroundColor Green
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    Write-Host ""

    $newUrl = $RequestedUrl
    if (-not $PSBoundParameters.ContainsKey("RequestedUrl") -or [string]::IsNullOrWhiteSpace($RequestedUrl)) {
        $inputUrl = Read-Host "Enter new PUBLIC_BASE_URL (press Enter to keep '$currentUrl')"
        if ([string]::IsNullOrWhiteSpace($inputUrl)) {
            Write-Host ""
            Write-Host "No change made. PUBLIC_BASE_URL remains: $currentUrl" -ForegroundColor Yellow
            return @{ Path = $Path; Content = $envContent }
        }
        $newUrl = $inputUrl.Trim()
    } else {
        $newUrl = $RequestedUrl.Trim()
    }

    if ($envContent -match '(?m)^PUBLIC_BASE_URL\s*=') {
        $newContent = $envContent -replace '(?m)^PUBLIC_BASE_URL\s*=.*$', "PUBLIC_BASE_URL=$newUrl"
    } else {
        $newContent = $envContent + "`nPUBLIC_BASE_URL=$newUrl"
    }
    Set-Content -Path $Path -Value $newContent -NoNewline
    Write-Host ""
    Write-Host "Successfully updated PUBLIC_BASE_URL to: $newUrl" -ForegroundColor Green
    return @{ Path = $Path; Content = $newContent }
}

function Wait-UntilHealthy {
    param([string]$Url, [int]$TimeoutSeconds = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $null = Invoke-RestMethod -Uri "$Url/api/v1/health" -TimeoutSec 2
            return
        } catch {
            Start-Sleep -Milliseconds 400
        }
    } while ((Get-Date) -lt $deadline)
    throw "Server at $Url did not become healthy within ${TimeoutSeconds}s."
}

function Invoke-BackendSmokeTest {
    param(
        [string]$Url,
        [string]$Token,
        [string]$Email,
        [double]$Amount,
        [switch]$OpenUrl
    )

    Write-Host "Testing ZenPay Reference Backend at $Url" -ForegroundColor Cyan

    Invoke-Step "Health check" {
        Invoke-RestMethod -Uri "$Url/api/v1/health"
    }

    $idempotencyKey = "test-key-" + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $session = Invoke-Step "Create checkout session" {
        Invoke-RestMethod -Method Post -Uri "$Url/api/v1/sessions" `
            -Headers @{
                Authorization     = "Bearer $Token"
                "Idempotency-Key" = $idempotencyKey
            } `
            -ContentType "application/json" `
            -Body (@{
                orderId       = "test-order-$idempotencyKey"
                customerName  = "Test Customer"
                customerEmail = $Email
                client        = "web"
                paymentAmount = $Amount
            } | ConvertTo-Json)
    }

    Invoke-Step "Look up the session by merchantUniquePaymentId" {
        Invoke-RestMethod -Uri "$Url/api/v1/sessions/$($session.merchantUniquePaymentId)" `
            -Headers @{ Authorization = "Bearer $Token" }
    }

    Write-Host ""
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    Write-Host "checkoutUrl:" -ForegroundColor Cyan
    Write-Host $session.checkoutUrl -ForegroundColor Green
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Opening it in a browser is the real correctness check: if ZenPay's" -ForegroundColor Yellow
    Write-Host "sandbox renders a checkout page instead of an error, the fingerprint" -ForegroundColor Yellow
    Write-Host "and URL are validated by ZenPay's own server, not just this script." -ForegroundColor Yellow

    if ($OpenUrl) {
        Start-Process $session.checkoutUrl
    } else {
        Write-Host ""
        Write-Host "Pass -OpenCheckoutUrl to open it automatically." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Not covered by this script: the callback path (POST /api/v1/callbacks)" -ForegroundColor Yellow
    Write-Host "only fires when ZenPay actually calls back after a real/sandbox payment." -ForegroundColor Yellow
}

function Stop-BackendServer {
    param($Process)
    if (-not $Process) { return }
    if ($Process.HasExited) { return }
    Write-Host ""
    Write-Host "Stopping server..." -ForegroundColor Cyan
    & taskkill.exe /PID $Process.Id /T /F 2>$null | Out-Null
}

$envFile = Resolve-EnvFilePath -ExplicitPath $EnvFilePath
$envContent = $null

if (-not $TestOnly) {
    $updated = Update-PublicBaseUrl -Path $envFile -RequestedUrl $PublicBaseUrl
    $envFile = $updated.Path
    $envContent = $updated.Content
} elseif (Test-Path (Resolve-EnvFilePath -ExplicitPath $EnvFilePath)) {
    $envFile = [string](Resolve-Path (Resolve-EnvFilePath -ExplicitPath $EnvFilePath))
    $envContent = Get-Content $envFile -Raw
}

if (-not $envContent -and (Test-Path $envFile)) {
    $envContent = Get-Content $envFile -Raw
}

if (-not $BearerToken -and $envContent) {
    $BearerToken = Get-EnvValue -Content $envContent -Name "MERCHANT_APP_BEARER_TOKEN"
}
if (-not $BearerToken) { $BearerToken = "local-demo-token" }

if (-not $BaseUrl) {
    $port = "7000"
    if ($envContent) {
        $fromEnv = Get-EnvValue -Content $envContent -Name "PORT"
        if ($fromEnv) { $port = $fromEnv }
    }
    $BaseUrl = "http://localhost:$port"
}

$serverProcess = $null
try {
    if (-not $TestOnly) {
        $exampleDir = Join-Path $PSScriptRoot "example"
        $dart = (Get-Command dart -ErrorAction Stop).Source

        Write-Host ""
        Write-Host "Starting ZenPay Reference Backend Server..." -ForegroundColor Cyan
        Write-Host ""

        $serverProcess = Start-Process -FilePath $dart `
            -ArgumentList @("run", "bin/server.dart") `
            -WorkingDirectory $exampleDir `
            -NoNewWindow `
            -PassThru

        Wait-UntilHealthy -Url $BaseUrl
    }

    if (-not $SkipTest) {
        Invoke-BackendSmokeTest `
            -Url $BaseUrl `
            -Token $BearerToken `
            -Email $CustomerEmail `
            -Amount $PaymentAmount `
            -OpenUrl:$OpenCheckoutUrl
    }

    if ($serverProcess -and -not $serverProcess.HasExited) {
        Write-Host ""
        Write-Host "Server is running. Press Ctrl+C to stop." -ForegroundColor Cyan
        Wait-Process -Id $serverProcess.Id
    }
} finally {
    Stop-BackendServer -Process $serverProcess
}
