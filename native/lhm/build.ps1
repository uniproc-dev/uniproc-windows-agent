param([string]$Destination)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$source = Join-Path $PSScriptRoot '.source'
$diskSource = Join-Path $PSScriptRoot '.diskinfo-source'
function PinnedSource([string]$Path, [string]$Url, [string]$Commit) {
    $fresh = -not (Test-Path -LiteralPath (Join-Path $Path '.git'))
    if ($fresh) {
        git clone --no-checkout $Url $Path
        if ($LASTEXITCODE -ne 0) { throw 'Source clone failed' }
    }
    if (-not $fresh) {
        $dirty = git -C $Path status --porcelain --untracked-files=no
        if ($dirty) { throw 'Cached source has tracked modifications' }
    }
    git -C $Path checkout --detach $Commit
    if ($LASTEXITCODE -ne 0 -or (git -C $Path rev-parse HEAD) -ne $Commit) { throw 'Pinned source checkout failed' }
}
PinnedSource $source 'https://github.com/LibreHardwareMonitor/LibreHardwareMonitor.git' '2808d80564b6761e1b01f42fabfd966ed695fcbc'
PinnedSource $diskSource 'https://github.com/Blacktempel/DiskInfoToolkit.git' '073a31312b9f5147340488e551e06df5f3ab9715'
$output = Join-Path $root 'target/lhm-native-aot'
$patches = @(
    @{ Source = $source; Path = (Join-Path $PSScriptRoot 'skip-unused-nvml.patch') },
    @{ Source = $source; Path = (Join-Path $PSScriptRoot 'diskinfo-project.patch') },
    @{ Source = $diskSource; Path = (Join-Path $PSScriptRoot 'stream-pci-ids.patch') }
)
$applied = [Collections.Generic.List[object]]::new()
Push-Location $PSScriptRoot
try {
    foreach ($patch in $patches) {
        git -C $patch.Source apply --check $patch.Path
        if ($LASTEXITCODE -ne 0) { throw 'Patch does not match pinned source' }
        git -C $patch.Source apply $patch.Path
        if ($LASTEXITCODE -ne 0) { throw 'Source patch failed' }
        $applied.Add($patch)
    }
    dotnet publish Uniproc.Lhm.csproj -c Release -f net10.0 -r win-x64 -o $output "-p:LhmSourceRoot=$source" "-p:DiskInfoToolkitSourceRoot=$diskSource" -p:TargetFrameworks=net10.0 -p:GeneratePackageOnBuild=false -p:RestoreLockedMode=true
    if ($LASTEXITCODE -ne 0) { throw 'NativeAOT publication failed' }
    dotnet run --project ../lhm-tests/PciLookupTests.csproj -c Release -p:TargetFrameworks=net10.0 -p:GeneratePackageOnBuild=false -p:RestoreLockedMode=true
    if ($LASTEXITCODE -ne 0) { throw 'PCI lookup compatibility tests failed' }
} finally {
    Pop-Location
    $restoreFailed = $false
    for ($index = $applied.Count - 1; $index -ge 0; $index--) {
        $patch = $applied[$index]
        git -C $patch.Source apply --reverse $patch.Path
        if ($LASTEXITCODE -ne 0) { $restoreFailed = $true }
    }
    if ($restoreFailed) { throw 'Cached source patches could not be reverted' }
}
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
    Copy-Item -LiteralPath (Join-Path $diskSource 'LICENSE') -Destination (Join-Path $licenses 'DiskInfoToolkit-LICENSE')
    foreach ($name in @('skip-unused-nvml.patch', 'diskinfo-project.patch', 'stream-pci-ids.patch', 'UNIPROC-MODIFICATIONS.txt')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $licenses
    }
}
