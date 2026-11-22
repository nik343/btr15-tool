# JVM regression: compile every non-Android source + all tests, run every selftest.
param(
    # Official / dev-signed packages the suites read: drop them in fixtures/
    # beside this script (not committed) or point -Fixtures somewhere else.
    [string]$Fixtures = (Join-Path $PSScriptRoot 'fixtures'),
    [string]$JavaHome
)
$ErrorActionPreference = 'Stop'
$ui = $PSScriptRoot
Set-Location $ui
if (-not $JavaHome) {
    if (-not $env:JAVA_HOME) { throw 'no JDK: pass -JavaHome or set JAVA_HOME' }
    $JavaHome = $env:JAVA_HOME
}
if (-not (Test-Path (Join-Path $JavaHome 'bin\javac.exe'))) { throw "no bin\javac.exe under JavaHome '$JavaHome'" }
$jdk = Join-Path $JavaHome 'bin'
if (-not (Test-Path (Join-Path $Fixtures 'BTR15_V3.8.bin'))) { throw "no packages in '$Fixtures': drop the official and dev-signed builds there or pass -Fixtures <dir>" }
$androidOnly = @('MainActivity.java','Btr15Connection.java','MnemonicStore.java','Btr15VectorIllustration.java','RfcommTransport.java','HoldToDiscardButton.java')
$src = (Get-ChildItem src\main\java\app\btr15\tool\*.java | Where-Object { $androidOnly -notcontains $_.Name }).FullName
$tests = (Get-ChildItem src\test\java\app\btr15\tool\*.java).FullName
& "$jdk\javac.exe" -encoding UTF-8 -d build\enginetest @src @tests
if ($LASTEXITCODE -ne 0) { throw 'javac failed' }
$official = Join-Path $Fixtures 'BTR15_V3.8.bin'
$candidate = Join-Path $Fixtures 'BTR15_V3.8_AUTOMUTE_DEVKEY_SIGNED.bin'
$v7 = Join-Path $Fixtures 'BTR15_V3.8_AUTOMUTE_DEVKEY_100HZ_MENU_V7_OFFICIAL_FONT_DEV_SIGNED.bin'
$v8 = Join-Path $Fixtures 'BTR15_V3.8_AUTOMUTE_DEVKEY_100HZ_100HZ2_DEADLINE_V8_DEV_SIGNED.bin'
$phase1 = Join-Path $Fixtures 'BTR15_V3.8_STOCK_PAYLOADS_DEV_SIGNED_PHASE1.bin'
$v22 = Join-Path $Fixtures 'BTR15_v2.2.bin'
$v35 = Join-Path $Fixtures 'BTR15_V3.5.bin'
$v44 = Join-Path $Fixtures 'BTR15_Bluetooth_V4.4.bin'
$notFirmware = Join-Path $ui 'build\not-a-firmware.bin'
Set-Content -Path $notFirmware -Value 'this is not an APPUHDR5 package' -NoNewline
foreach ($t in @(@('Bip39SelfTest'), @('DevKeySelfTest'), @('ProtocolSelfTest'), @('CrossProof'),
                 @('FirmwareInspectorSelfTest', $official, $notFirmware, $candidate, $v8, $phase1),
                 @('FirmwareEngineSelfTest', $official, $candidate, $v7, $v8, $phase1, $v22, $v35, $v44),
                 @('WorkflowSelfTest', $official), @('IntegrationSelfTest', $official, $v35, $v44))) {
    $name = $t[0]
    $out = & "$jdk\java.exe" -cp build\enginetest "app.btr15.tool.$name" @($t[1..($t.Count-1)]) 2>&1
    if ($LASTEXITCODE -ne 0) { $out | Select-Object -Last 12; throw "$name FAILED" }
    Write-Host ("{0} => {1}" -f $name, ($out | Select-Object -Last 1))
}
Write-Host 'ALL JVM SELFTESTS PASS'
