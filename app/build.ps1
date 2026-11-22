param(
    # Siblings of the repo by convention (they are not committed): pass these
    # for your own install.
    [string]$SdkRoot = (Join-Path $PSScriptRoot '..\work\android_sdk'),
    [string]$SigningDir = (Join-Path $PSScriptRoot '..\work\release_signing'),
    [string]$JavaHome,
    # Optional pins. By default the newest installed platform and the newest
    # build-tools that actually carry the tools this build calls are used.
    [string]$AndroidPlatform,
    [string]$BuildToolsVersion
)

$ErrorActionPreference = 'Stop'
# App properties, not environment: these are what the built manifest says.
$MinSdk = 23
$TargetSdk = 35

if (-not $JavaHome) {
    if (-not $env:JAVA_HOME) { throw 'no JDK: pass -JavaHome or set JAVA_HOME' }
    $JavaHome = $env:JAVA_HOME
}
if (-not (Test-Path (Join-Path $JavaHome 'bin\javac.exe'))) { throw "no bin\javac.exe under JavaHome '$JavaHome'" }
# d8.bat and apksigner.bat find java through JAVA_HOME and PATH.
$env:JAVA_HOME = $JavaHome
$env:PATH = (Join-Path $JavaHome 'bin') + ';' + $env:PATH

if (-not (Test-Path $SdkRoot)) { throw "Android SDK not found at '$SdkRoot': pass -SdkRoot" }
$SdkRoot = (Resolve-Path $SdkRoot).Path

if (-not $AndroidPlatform) {
    $platforms = Get-ChildItem -Path (Join-Path $SdkRoot 'platforms') -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^android-(\d+)$' -and (Test-Path (Join-Path $_.FullName 'android.jar')) } |
        Sort-Object { [int]($_.Name -replace '^android-', '') } -Descending
    if (-not $platforms) { throw "no Android platform with an android.jar under '$SdkRoot\platforms': pass -AndroidPlatform" }
    $AndroidPlatform = $platforms[0].Name
}
$AndroidJar = Join-Path $SdkRoot 'platforms' | Join-Path -ChildPath $AndroidPlatform | Join-Path -ChildPath 'android.jar'
if (-not (Test-Path $AndroidJar)) { throw "no android.jar for platform '$AndroidPlatform' under '$SdkRoot\platforms'" }

if (-not $BuildToolsVersion) {
    $toolDirs = Get-ChildItem -Path (Join-Path $SdkRoot 'build-tools') -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+(\.\d+)+$' -and
            (Test-Path (Join-Path $_.FullName 'aapt2.exe')) -and
            (Test-Path (Join-Path $_.FullName 'd8.bat')) -and
            (Test-Path (Join-Path $_.FullName 'zipalign.exe')) -and
            (Test-Path (Join-Path $_.FullName 'apksigner.bat')) } |
        Sort-Object { [version]$_.Name } -Descending
    if (-not $toolDirs) { throw "no build-tools with aapt2, d8, zipalign and apksigner under '$SdkRoot\build-tools': pass -BuildToolsVersion" }
    $BuildToolsVersion = $toolDirs[0].Name
}
$BuildTools = Join-Path $SdkRoot 'build-tools' | Join-Path -ChildPath $BuildToolsVersion
if (-not (Test-Path (Join-Path $BuildTools 'aapt2.exe'))) { throw "build-tools '$BuildToolsVersion' is not usable under '$SdkRoot\build-tools'" }
Write-Host "SDK $SdkRoot | platform $AndroidPlatform | build-tools $BuildToolsVersion | JDK $JavaHome"
$BuildDir = Join-Path $PSScriptRoot 'build'
$ClassesDir = Join-Path $BuildDir 'classes-neutral'
$DexDir = Join-Path $BuildDir 'dex-neutral'
$ResourceDir = Join-Path $PSScriptRoot 'src\main\res'
# Compiled as loose .flat files, not one zip: a values resource inside a -R
# overlay zip is rejected ("does not override an existing resource") and a
# second build appends into the same zip.
$CompiledResources = Join-Path $BuildDir 'res-flat'
$UnsignedApk = Join-Path $BuildDir 'btr15-tool-unsigned.apk'
$UnalignedApk = Join-Path $BuildDir 'btr15-tool-unaligned.apk'
$AlignedApk = Join-Path $BuildDir 'btr15-tool-aligned.apk'
$FinalApk = Join-Path $BuildDir 'btr15-tool.apk'
$Keystore = Join-Path $SigningDir 'btr15-release.keystore'
$PasswordFile = Join-Path $SigningDir 'password.txt'
$Alias = 'btr15-release'

New-Item -ItemType Directory -Force -Path $BuildDir,$ClassesDir,$DexDir | Out-Null

$Sources = Get-ChildItem -Path (Join-Path $PSScriptRoot 'src\main\java') -Recurse -Filter '*.java' |
    ForEach-Object { $_.FullName }
# The frozen vector suites ship inside the APK so `am start --ez run_selftest
# true` can re-prove the frozen vectors on the device itself (proof.ps1).
$Sources += @('Bip39SelfTest.java','DevKeySelfTest.java','ProtocolSelfTest.java') |
    ForEach-Object { (Join-Path $PSScriptRoot (Join-Path 'src\test\java\app\btr15\tool' $_)).ToString() }
& (Join-Path $JavaHome 'bin\javac.exe') -encoding UTF-8 -source 8 -target 8 `
    -classpath $AndroidJar -d $ClassesDir $Sources
if ($LASTEXITCODE -ne 0) { throw 'javac failed' }

$ClassFiles = Get-ChildItem -Path $ClassesDir -Recurse -Filter '*.class' |
    ForEach-Object { $_.FullName }
# d8 reads @-response files natively; passing every .class path on the
# command line exceeds the Windows cmd limit once the suites ship in the APK.
$D8ArgFile = Join-Path $BuildDir 'd8-classes.rsp'
Set-Content -Path $D8ArgFile -Encoding ASCII -Value ($ClassFiles |
    ForEach-Object { $_ -replace '\\', '/' })
& (Join-Path $BuildTools 'd8.bat') --min-api $MinSdk --lib $AndroidJar --output $DexDir ('@' + $D8ArgFile)
if ($LASTEXITCODE -ne 0) { throw 'd8 failed' }

# aapt2 compile appends into an existing output, so start the container fresh.
Remove-Item -LiteralPath $CompiledResources -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $CompiledResources | Out-Null
& (Join-Path $BuildTools 'aapt2.exe') compile --dir $ResourceDir -o $CompiledResources
if ($LASTEXITCODE -ne 0) { throw 'aapt2 compile failed' }

$ResArgFile = Join-Path $BuildDir 'aapt2-res.rsp'
Get-ChildItem -Path $CompiledResources -Recurse -Filter '*.flat' |
    ForEach-Object { $_.FullName -replace '\\', '/' } |
    Set-Content -Path $ResArgFile -Encoding ASCII

& (Join-Path $BuildTools 'aapt2.exe') link -I $AndroidJar `
    --manifest (Join-Path $PSScriptRoot 'AndroidManifest.xml') `
    --min-sdk-version $MinSdk --target-sdk-version $TargetSdk `
    -o $UnsignedApk ('@' + $ResArgFile)
if ($LASTEXITCODE -ne 0) { throw 'aapt2 link failed' }

Copy-Item -LiteralPath $UnsignedApk -Destination $UnalignedApk -Force
Push-Location $DexDir
try {
    & (Join-Path $JavaHome 'bin\jar.exe') uf $UnalignedApk 'classes.dex'
    if ($LASTEXITCODE -ne 0) { throw 'adding classes.dex failed' }
} finally {
    Pop-Location
}

& (Join-Path $BuildTools 'zipalign.exe') -f 4 $UnalignedApk $AlignedApk
if ($LASTEXITCODE -ne 0) { throw 'zipalign failed' }

if (-not (Test-Path $Keystore)) {
    # First run on this machine: make the release key and keep its password
    # beside it.  From then on every update must be signed with this very key,
    # because Android only installs an update over a build signed by the same
    # certificate — losing it means an uninstall (and a lost mnemonic).
    New-Item -ItemType Directory -Force -Path $SigningDir | Out-Null
    $pass = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 28 |
            ForEach-Object { [char]$_ })
    Set-Content -Path $PasswordFile -Value $pass -NoNewline -Encoding ASCII
    & (Join-Path $JavaHome 'bin\keytool.exe') -genkeypair -noprompt `
        -keystore $Keystore -storetype PKCS12 -storepass $pass -keypass $pass `
        -alias $Alias -keyalg RSA -keysize 4096 -validity 10000 `
        -dname 'CN=BTR15 Tool, O=BTR15 Tool, C=US'
    if ($LASTEXITCODE -ne 0) { throw 'keytool failed' }
    Write-Host "Created the release key: $Keystore (password in $PasswordFile)"
}
$StorePass = (Get-Content -LiteralPath $PasswordFile -Raw).Trim()
if ([string]::IsNullOrEmpty($StorePass)) { throw "empty key password in $PasswordFile" }

& (Join-Path $BuildTools 'apksigner.bat') sign --ks $Keystore `
    --ks-key-alias $Alias --ks-pass "pass:$StorePass" --key-pass "pass:$StorePass" `
    --v4-signing-enabled false `
    --out $FinalApk $AlignedApk
if ($LASTEXITCODE -ne 0) { throw 'apksigner failed' }

& (Join-Path $BuildTools 'apksigner.bat') verify --verbose --print-certs $FinalApk
if ($LASTEXITCODE -ne 0) { throw 'APK signature verification failed' }

& (Join-Path $BuildTools 'aapt2.exe') dump xmltree --file AndroidManifest.xml $FinalApk `
    | Select-String -Pattern 'debuggable'
Get-FileHash -Algorithm SHA256 $FinalApk
Get-Item $FinalApk | Select-Object FullName,Length
