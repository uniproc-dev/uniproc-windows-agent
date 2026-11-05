param([string]$Destination)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$source = Join-Path $root 'target/lhm-source'
$commit = '2808d80564b6761e1b01f42fabfd966ed695fcbc'
if (-not (Test-Path -LiteralPath (Join-Path $source '.git'))) {
    git clone --no-checkout https://github.com/LibreHardwareMonitor/LibreHardwareMonitor.git $source
    if ($LASTEXITCODE -ne 0) { throw 'LHM clone failed' }
}
git -C $source checkout --detach $commit
if ($LASTEXITCODE -ne 0) { throw 'Pinned LHM checkout failed' }
$actual = git -C $source rev-parse HEAD
if ($actual -ne $commit) { throw 'Unexpected LHM revision' }
$dirty = git -C $source status --porcelain --untracked-files=no
if ($dirty) { throw 'LHM source has tracked modifications' }
$output = Join-Path $root 'target/lhm-native-aot'
Push-Location $PSScriptRoot
try {
    dotnet publish Uniproc.Lhm.csproj -c Release -f net10.0 -r win-x64 -o $output "-p:LhmSourceRoot=$source" -p:TargetFrameworks=net10.0 -p:GeneratePackageOnBuild=false -p:RestoreLockedMode=true
    if ($LASTEXITCODE -ne 0) { throw 'NativeAOT publication failed' }
} finally { Pop-Location }
if ($Destination) {
    $target = [IO.Path]::GetFullPath($Destination)
    if (-not (Test-Path -LiteralPath $target -PathType Container)) { throw 'Deployment destination does not exist' }
    Get-ChildItem -LiteralPath $output -Filter '*.dll' -File | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $target
    }
    $licenses = Join-Path $target 'lhm-licenses'
    New-Item -ItemType Directory -Path $licenses -Force | Out-Null
    foreach ($name in @('LICENSE', 'THIRD-PARTY-NOTICES.txt')) {
        Copy-Item -LiteralPath (Join-Path $source $name) -Destination $licenses
    }
}
