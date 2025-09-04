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

# -------- Day 4: Auto-Responder demo --------
# 1) Generate detections (Day 2)
$detections = Join-Path $PSScriptRoot "..\sample_logs\detections.jsonl"
python ..\cli.py detect run ..\sample_logs\apache_access.jsonl --out $detections

# 2) Dry-run responder (no real changes to system)
python ..\cli.py respond run $detections --dry-run

# 3) Real run (be sure you understand actions; block_ip will add a Windows FW rule)
# (Optional) Set Slack/email env vars if you have notify actions referencing alert routes
# $env:SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/..."
# $env:SMTP_USERNAME = "user@example.com"
# $env:SMTP_PASSWORD = "********"
python ..\cli.py respond run $detections



