# Clockwork proof for the BTR15 tool.
#
#   1. Runs every JVM selftest suite on this PC (crypto vectors, wire frames,
#      firmware engine, workflow power-loss sweeps, integration lifecycle).
#   2. Builds the APK and installs it on the phone.
#   3. Starts the app in run_selftest mode ON THE PHONE, which re-runs the
#      frozen BIP-39 / BDKD-v1 / GAIA vector suites plus the pinned CrossProof
#      digests inside Android's runtime and writes the results to logcat.
#   4. Diffs the phone's proof lines against the PC's.  Identical lines prove
#      both machines derive bit-identical developer keys and sign/verify
#      identically — the exact arithmetic the flashing path runs on.
#
# Usage:  pwsh -NoProfile -File app\proof.ps1
#         pwsh -NoProfile -File app\proof.ps1 -PcOnly
#         pwsh -NoProfile -File app\proof.ps1 -Serial <host:port>
param(
    # Required for a phone run; -PcOnly does not need it.
    [string]$Serial,
    # Sibling of the repo by convention (it is not committed).
    [string]$SdkRoot = (Join-Path (Split-Path $PSScriptRoot) 'work\android_sdk'),
    [string]$JavaHome,
    # Sibling of the repo by convention; the release key lives outside the app
    # tree because the repo ships no private key.
    [string]$SigningDir = (Join-Path (Split-Path $PSScriptRoot) 'work\release_signing'),
    [switch]$PcOnly
)
$ErrorActionPreference = 'Stop'
$ui = $PSScriptRoot
if (-not $JavaHome) {
    if (-not $env:JAVA_HOME) { throw 'no JDK: pass -JavaHome or set JAVA_HOME' }
    $JavaHome = $env:JAVA_HOME
}
if (-not (Test-Path (Join-Path $JavaHome 'bin\javac.exe'))) { throw "no bin\javac.exe under JavaHome '$JavaHome'" }
$jdk = Join-Path $JavaHome 'bin'
if (-not $PcOnly) {
    if (-not $Serial) { throw 'pass -Serial <host:port> for the phone half, or -PcOnly' }
    $adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
    if (-not (Test-Path $adb)) { $adb = (Get-Command adb -ErrorAction SilentlyContinue).Source }
    if (-not $adb) { throw "adb not found: pass -SdkRoot or put adb on PATH" }
}

function Get-ProofLines([string]$text) {
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($line in ($text -split "`n")) {
        if ($line -match '(XPROOF [^ ]+=[^ ]+(?: MATCH| MISMATCH)?)') {
            $out.Add($Matches[1])
        } elseif ($line -match '((?:BIP-39 self-test passed|DevKeySelfTest: PASS|ProtocolSelfTest: PASS).*)$') {
            $out.Add($Matches[1].Trim())
        }
    }
    return ,$out.ToArray()
}

Write-Host '== [1/4] PC: all JVM selftest suites ==' -ForegroundColor Cyan
& pwsh -NoProfile -File (Join-Path $ui 'run-jvm-selftests.ps1') -JavaHome $JavaHome
if ($LASTEXITCODE -ne 0) { throw 'PC selftests FAILED' }

Write-Host '== [2/4] PC: proof lines (frozen suites + CrossProof) ==' -ForegroundColor Cyan
$classes = Join-Path $ui 'build\enginetest'
$pcText = ''
foreach ($m in @('Bip39SelfTest','DevKeySelfTest','ProtocolSelfTest','CrossProof')) {
    $r = & "$jdk\java.exe" -cp $classes "app.btr15.tool.$m" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "PC $m FAILED" }
    $pcText += ($r -join "`n") + "`n"
}
($pcText -split "`n") | Where-Object { $_ -match 'XPROOF' } |
    ForEach-Object { Write-Host "  $_" }

if ($PcOnly) {
    Write-Host 'PC-only proof complete.' -ForegroundColor Green
    return
}

Write-Host '== [3/4] Build APK and install on phone ==' -ForegroundColor Cyan
& pwsh -NoProfile -File (Join-Path $ui 'build.ps1') -SdkRoot $SdkRoot -JavaHome $JavaHome -SigningDir $SigningDir | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'APK build FAILED' }
$apk = Join-Path $ui 'build\btr15-tool.apk'
& $adb connect $Serial | Out-Null
$installed = & $adb -s $Serial install -r $apk 2>&1
if ($LASTEXITCODE -ne 0) {
    # The release certificate replaced the preview one, and Android only
    # installs an update signed by the same key: the old build has to go, which
    # takes the phone's saved mnemonic with it.  Back it up before switching.
    Write-Host 'update install refused — removing the previous certificate build first'
    Write-Host ($installed | Select-Object -Last 2)
    & $adb -s $Serial uninstall app.btr15.tool | Out-Null
    & $adb -s $Serial install $apk
    if ($LASTEXITCODE -ne 0) { throw 'adb install FAILED' }
}

Write-Host '== [4/4] Phone: run frozen suites in app runtime, diff vs PC ==' -ForegroundColor Cyan
& $adb -s $Serial shell am force-stop app.btr15.tool
# The file picker can be left resumed on top of the app's task; if it is, the
# extra would be delivered to it and the app would never run its onCreate.
& $adb -s $Serial shell am force-stop com.google.android.documentsui
# Wait for the process to be gone: an `am start` that lands while the old
# instance is still alive only delivers the extra to that instance, whose
# onCreate already ran, and the proof then sees no output at all.
$gone = (Get-Date).AddSeconds(15)
while ((Get-Date) -lt $gone) {
    $runningPid = (& $adb -s $Serial shell pidof app.btr15.tool) -join ''
    if ([string]::IsNullOrWhiteSpace($runningPid)) { break }
    Start-Sleep -Milliseconds 300
}
& $adb -s $Serial logcat -c | Out-Null
& $adb -s $Serial shell am start -n app.btr15.tool/.MainActivity --ez run_selftest true | Out-Null
$deadline = (Get-Date).AddSeconds(240)
$log = ''
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    $log = (& $adb -s $Serial logcat -d 2>&1) -join "`n"
    if ($log -match 'XPROOF DONE') { break }
}
if ($log -notmatch 'XPROOF DONE PASS') {
    Write-Host ($log -split "`n" | Select-String 'XPROOF|System.out|Btr15Proof' | Select-Object -Last 30)
    throw 'phone proof missing or FAILED (no XPROOF DONE PASS in logcat)'
}
$phoneLines = Get-ProofLines $log
$pcLines = Get-ProofLines $pcText
$drift = Compare-Object -ReferenceObject $pcLines -DifferenceObject $phoneLines
Write-Host '  phone proof lines:' -ForegroundColor DarkGray
$phoneLines | ForEach-Object { Write-Host "    $_" }
if ($drift) {
    $drift | Format-Table | Out-String | Write-Host
    throw 'phone proof differs from PC proof'
}

Write-Host ''
Write-Host 'CLOCKWORK PROOF: PASS' -ForegroundColor Green
Write-Host '  - every JVM suite green on PC (vectors, engine, workflows, integration)'
Write-Host '  - BIP-39, BDKD-v1 and GAIA vector suites green inside Android runtime'
Write-Host '  - phone and PC proof lines identical (bit-identical key derivation)'
Write-Host '  - RSA-PSS sign/verify roundtrip plus tamper rejection on both machines'
