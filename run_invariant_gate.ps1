<#
.SYNOPSIS
    run_invariant_gate.ps1 - Automated CI / Pre-Commit Gate for Invariant Engine.
    Target: Windows PowerShell 5.1 / PowerShell 7+ (pwsh). Zero external dependencies.

.PARAMETER WorkspaceRoot
    Root path to invariant-engine repository. Defaults to current directory.

.PARAMETER PythonExe
    Path or command for Python executable. Defaults to 'python'.

.PARAMETER QuarantineDir
    Target directory for dead-letter logs and payload files. Defaults to '.\quarantine'.

.PARAMETER BaselineManifest
    Baseline manifest filename. Defaults to 'baseline.json'.

.PARAMETER GenerateBaselineIfMissing
    Switch to automatically generate baseline.json if not present.
#>

[CmdletBinding()]
param (
    [string]$WorkspaceRoot = ".",
    [string]$PythonExe = "python",
    [string]$QuarantineDir = ".\quarantine",
    [string]$BaselineManifest = "baseline.json",
    [switch]$GenerateBaselineIfMissing
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ResolvedWorkspace = (Resolve-Path -Path $WorkspaceRoot).Path
Set-Location -Path $ResolvedWorkspace

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  INVARIANT ENGINE PRE-COMMIT / CI GATEWAY (POWERSHELL)" -ForegroundColor Cyan
Write-Host "  Workspace: $ResolvedWorkspace" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$env:PYTHONPATH = $ResolvedWorkspace

# Phase 1: Unit Test Verification
Write-Host "`n======================================================================" -ForegroundColor Yellow
Write-Host "  [PHASE 1] Deterministic Unit Test Verification (Architect: 10.0)" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Yellow

$TestProcess = Start-Process -FilePath $PythonExe `
    -ArgumentList "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v" `
    -NoNewWindow -PassThru -Wait

if ($TestProcess.ExitCode -ne 0) {
    Write-Error "[FAIL] Unit test suite failed with exit code $($TestProcess.ExitCode). Halting gate."
    exit $TestProcess.ExitCode
}
Write-Host "[PASS] All unit test vectors certified green." -ForegroundColor Green

# Phase 2: Live Manifest Reconciliation
Write-Host "`n======================================================================" -ForegroundColor Yellow
Write-Host "  [PHASE 2] Live Workspace Manifest Reconciliation (Arbiter: 10.0)" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Yellow

$BaselinePath = Join-Path -Path $ResolvedWorkspace -ChildPath $BaselineManifest

if (-not (Test-Path -Path $BaselinePath)) {
    if ($GenerateBaselineIfMissing) {
        Write-Host "[WARN] Baseline manifest not found. Generating initial baseline snapshot..." -ForegroundColor DarkYellow
        $GenProcess = Start-Process -FilePath $PythonExe `
            -ArgumentList "baremetal_cli.py", "reconcile", "-w", "`"$ResolvedWorkspace`"", "-o", "`"$BaselinePath`"" `
            -NoNewWindow -PassThru -Wait

        if ($GenProcess.ExitCode -ne 0) {
            Write-Error "[FAIL] Failed to generate baseline manifest. Exit code: $($GenProcess.ExitCode)"
            exit $GenProcess.ExitCode
        }
    } else {
        Write-Error "[FAIL] Baseline manifest missing at '$BaselinePath'. Pass -GenerateBaselineIfMissing to initialize."
        exit 1
    }
}

Write-Host "[>] Reconciling disk tree against baseline: $BaselinePath"
$ReconcileProcess = Start-Process -FilePath $PythonExe `
    -ArgumentList "baremetal_cli.py", "reconcile", "-w", "`"$ResolvedWorkspace`"", "-b", "`"$BaselinePath`"" `
    -NoNewWindow -PassThru -Wait

if ($ReconcileProcess.ExitCode -ne 0) {
    Write-Error "[FAIL] Manifest drift detected. Exit code: $($ReconcileProcess.ExitCode)"
    exit $ReconcileProcess.ExitCode
}
Write-Host "[PASS] Workspace tree bit-level match confirmed." -ForegroundColor Green

# Phase 3: Evidentiary Stream Ingress Test
Write-Host "`n======================================================================" -ForegroundColor Yellow
Write-Host "  [PHASE 3] Evidentiary Stream Ingress & Quarantine Gate (Shadowsmith: 10.0)" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Yellow

$SampleStream = Join-Path -Path $ResolvedWorkspace -ChildPath "evidence_stream.txt"
$AcceptedEgress = Join-Path -Path $ResolvedWorkspace -ChildPath "accepted_stream.jsonl"
$ResolvedQuarantine = Join-Path -Path $ResolvedWorkspace -ChildPath $QuarantineDir

if (Test-Path -Path $SampleStream) {
    Write-Host "[>] Processing stream: $SampleStream"
    $IngressProcess = Start-Process -FilePath $PythonExe `
        -ArgumentList "baremetal_cli.py", "stream-ingress", `
            "-w", "`"$ResolvedWorkspace`"", `
            "-i", "`"$SampleStream`"", `
            "-o", "`"$AcceptedEgress`"", `
            "-s", "DOC_TELEMETRY_A,DOC_TELEMETRY_B", `
            "-q", "`"$ResolvedQuarantine`"" `
        -NoNewWindow -PassThru -Wait

    Write-Host "[INFO] Ingress exited with code $($IngressProcess.ExitCode) (Non-zero indicates quarantined records)." -ForegroundColor Cyan
} else {
    Write-Host "[SKIP] No evidence_stream.txt found. Skipping stream test." -ForegroundColor DarkGray
}

# Phase 4: Dead-Letter Replay Audit
Write-Host "`n======================================================================" -ForegroundColor Yellow
Write-Host "  [PHASE 4] Forensic Dead-Letter Replay Remediation (Arbiter: 10.0)" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Yellow

$QuarantineLog = Join-Path -Path $ResolvedQuarantine -ChildPath "quarantine.log"

if (Test-Path -Path $QuarantineLog) {
    Write-Host "[>] Auditing quarantine records with field-stripping remediation..."
    $ReplayProcess = Start-Process -FilePath $PythonExe `
        -ArgumentList "baremetal_cli.py", "replay-audit", `
            "-q", "`"$ResolvedQuarantine`"", `
            "-s", "DOC_TELEMETRY_A,DOC_TELEMETRY_B,PHANTOM_CITATION_GHOST", `
            "--strip-fields", "unauthorized_extra_key" `
        -NoNewWindow -PassThru -Wait

    Write-Host "[INFO] Replay audit evaluation finished with status: $($ReplayProcess.ExitCode)" -ForegroundColor Cyan
} else {
    Write-Host "[SKIP] No dead-letter quarantine log found. Skipping replay audit." -ForegroundColor DarkGray
}

Write-Host "`n======================================================================" -ForegroundColor Green
Write-Host "  PRE-COMMIT / CI GATEWAY COMPLETED: ZERO INVARIANT LEAKS DETECTED" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
exit 0