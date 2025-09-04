# Demo pipeline for Windows PowerShell
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $repoRoot  # back to repo root

$envPath = Join-Path $repoRoot ".venv"
$python = Join-Path $envPath "Scripts\python.exe"

if (-Not (Test-Path $python)) {
  Write-Host "Virtualenv not found at .venv. Please create and install requirements first." -ForegroundColor Yellow
  exit 1
}

$inputLog = Join-Path $repoRoot "sample_logs\apache_access.log"
$parsedJsonl = Join-Path $repoRoot "sample_logs\apache_access.jsonl"
$detections = Join-Path $repoRoot "detections.jsonl"

# Ingest
& $python "$repoRoot\cli.py" ingest file $inputLog --out $parsedJsonl

# Detect
& $python "$repoRoot\cli.py" detect run $parsedJsonl --rules "$repoRoot\rules\detection_rules.yaml" --out $detections --pretty

Write-Host "Wrote detections to $detections" -ForegroundColor Green

# 1) Run detection and write to a file
$detections = Join-Path $PSScriptRoot "..\sample_logs\detections.jsonl"
python ..\cli.py detect run ..\sample_logs\apache_access.jsonl --output $detections

# 2) Send alerts in dry-run mode (prints to console)
python ..\cli.py alert run $detections --dry-run


