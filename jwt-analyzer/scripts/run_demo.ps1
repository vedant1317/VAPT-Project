[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$NoOpenReports,
    [string]$OutputDir = "reports/demo-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
)

$ErrorActionPreference = "Stop"

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    Write-Host "`n==> $Name" -ForegroundColor Cyan
    & $Action
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = (Resolve-Path (Join-Path $scriptRoot "..")).Path
Set-Location $projectRoot

$repoVenvPython = (Resolve-Path (Join-Path $projectRoot "..\.venv\Scripts\python.exe") -ErrorAction SilentlyContinue)
if ($repoVenvPython) {
    $pythonExe = $repoVenvPython.Path
} else {
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCmd) {
        throw "Python executable not found. Configure .venv or install Python."
    }
    $pythonExe = $pythonCmd.Path
}

$outputRoot = if ([System.IO.Path]::IsPathRooted($OutputDir)) {
    $OutputDir
} else {
    Join-Path $projectRoot $OutputDir
}
New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null

$goodSecret = "demo_secret_value_longer_than_32_chars"
$weakSecret = "secret"

Invoke-Step -Name "Python interpreter" -Action {
    & $pythonExe --version
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to execute Python interpreter."
    }
}

if (-not $SkipTests) {
    Invoke-Step -Name "Run test suite" -Action {
        & $pythonExe -m pytest -q
        if ($LASTEXITCODE -ne 0) {
            throw "Test suite failed."
        }
    }
}

Invoke-Step -Name "Generate demo tokens" -Action {
    $scriptGood = "import jwt,time; print(jwt.encode({'sub':'demo-user','iss':'demo','aud':'demo-api','exp':int(time.time())+3600}, '$goodSecret', algorithm='HS256'))"
    $scriptWeak = "import jwt; print(jwt.encode({'sub':'admin'}, '$weakSecret', algorithm='HS256'))"

    $script:goodToken = (& $pythonExe -c $scriptGood).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $script:goodToken) {
        throw "Failed to generate baseline token."
    }

    $script:weakToken = (& $pythonExe -c $scriptWeak).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $script:weakToken) {
        throw "Failed to generate weak token."
    }
}

$goodHtml = Join-Path $outputRoot "good-report.html"
$goodStdout = Join-Path $outputRoot "good-output.txt"

$weakHtml = Join-Path $outputRoot "weak-report.html"
$weakStdout = Join-Path $outputRoot "weak-output.txt"

$invalidOutput = Join-Path $outputRoot "invalid-token-output.txt"

Invoke-Step -Name "Scenario 1: Healthy token analysis" -Action {
    $healthyOutput = & $pythonExe .\main.py --token $script:goodToken --known-secret $goodSecret --report --output $goodHtml 2>&1
    $healthyOutput | Set-Content -Encoding UTF8 $goodStdout
    if ($LASTEXITCODE -ne 0) {
        throw "Healthy token scenario failed."
    }
}

Invoke-Step -Name "Scenario 2: Weak secret and claim issues" -Action {
    $weakOutput = & $pythonExe .\main.py --token $script:weakToken --known-secret $weakSecret --report --output $weakHtml 2>&1
    $weakOutput | Set-Content -Encoding UTF8 $weakStdout
    if ($LASTEXITCODE -ne 0) {
        throw "Weak token scenario failed."
    }
}

Invoke-Step -Name "Scenario 3: Malformed token error handling" -Action {
    $badOutput = & $pythonExe .\main.py --token "invalid.jwt" 2>&1
    $exitCode = $LASTEXITCODE
    $badOutput | Set-Content -Encoding UTF8 $invalidOutput

    if ($exitCode -ne 2) {
        throw "Malformed token scenario expected exit code 2 but got $exitCode."
    }
}

Write-Host "`nDemo artifacts generated:" -ForegroundColor Green
Write-Host "- $goodHtml"
Write-Host "- $weakHtml"
Write-Host "- $goodStdout"
Write-Host "- $weakStdout"
Write-Host "- $invalidOutput"

if (-not $NoOpenReports) {
    Invoke-Step -Name "Open report files" -Action {
        Start-Process $goodHtml | Out-Null
        Start-Process $weakHtml | Out-Null
    }
}

Write-Host "`nDemo run complete." -ForegroundColor Green
