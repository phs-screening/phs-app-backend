param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("patient-selection", "form-save")]
  [string]$Scenario,

  [ValidateSet("single-user", "active-50", "burst-50")]
  [string]$Profile = "single-user",

  [string]$ResultName
)

$ErrorActionPreference = "Stop"

foreach ($requiredName in @("LOGIN_EMAIL", "LOGIN_PASSWORD")) {
  if (-not [Environment]::GetEnvironmentVariable($requiredName)) {
    throw "Set `$env:$requiredName before running this performance scenario."
  }
}

if (-not $env:PATIENT_IDS -and -not $env:PATIENT_IDS_FILE) {
  throw "Set either `$env:PATIENT_IDS or `$env:PATIENT_IDS_FILE."
}

$backendRoot = Split-Path -Parent $PSScriptRoot
$frontendRoot = Join-Path (Split-Path -Parent $backendRoot) "phs-app"
$scenarioPath = Join-Path $PSScriptRoot "scenarios\$Scenario.js"

if ($env:PATIENT_IDS_FILE) {
  $patientIdsPath = $env:PATIENT_IDS_FILE
  if (-not [System.IO.Path]::IsPathRooted($patientIdsPath)) {
    $patientIdsPath = Join-Path $backendRoot $patientIdsPath
  }
  $env:PATIENT_IDS_FILE = (Resolve-Path -LiteralPath $patientIdsPath).Path
}

if (-not (Get-Command k6 -ErrorAction SilentlyContinue)) {
  throw "k6 is not installed or is not available on PATH."
}

$env:PERF_SCENARIO = $Scenario
$env:PERF_PROFILE = $Profile
$env:BACKEND_COMMIT = (git -C $backendRoot rev-parse HEAD).Trim()

if (Test-Path $frontendRoot) {
  $env:FRONTEND_COMMIT = (git -C $frontendRoot rev-parse HEAD).Trim()
}

if ($ResultName) {
  if ($ResultName -notmatch "^[A-Za-z0-9._-]+$") {
    throw "ResultName may contain only letters, numbers, dots, underscores, and hyphens."
  }

  $resultsRoot = Join-Path $PSScriptRoot "results"
  $env:PERF_MARKDOWN_OUTPUT = Join-Path $resultsRoot "$ResultName.md"
  $env:PERF_JSON_OUTPUT = Join-Path $resultsRoot "$ResultName.json"
}

& k6 run $scenarioPath
exit $LASTEXITCODE
