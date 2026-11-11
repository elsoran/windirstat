param(
    [Parameter(Mandatory)] [string] $Destination,
    [Parameter(Mandatory)] [string] $Version,
    [Parameter(Mandatory)] [string] $Sha256
)

# Normalize module path issues
$env:PSModulePath = Join-Path ([System.Environment]::SystemDirectory) '\WindowsPowerShell\v1.0\Modules'

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression

function Copy-ZipEntry {
    param($Archive, [string] $Name, [string] $Dest)
    $entry = $null
    foreach ($candidate in $Archive.Entries) {
        if ([IO.Path]::GetFileName($candidate.FullName) -eq $Name) { $entry = $candidate; break }
    }
    if (-not $entry) { throw "miniz archive is missing $Name" }
    $source = $entry.Open()
    try {
        $output = [IO.File]::Create($Dest)
        try { $source.CopyTo($output) } finally { $output.Dispose() }
    } finally { $source.Dispose() }
}

$destination = [IO.Path]::GetFullPath($Destination)
$headerPath = Join-Path $destination 'miniz.h'
$sourcePath = Join-Path $destination 'miniz.c'
$stampPath = Join-Path $destination "miniz-$Version-$Sha256.stamp"
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$archive = Join-Path ([IO.Path]::GetTempPath()) ('miniz-' + [guid]::NewGuid().ToString('n') + '.zip')
try {
    Invoke-WebRequest -Uri "https://github.com/richgel999/miniz/releases/download/$Version/miniz-$Version.zip" `
        -OutFile $archive -UseBasicParsing
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256.ToLowerInvariant()) { throw "miniz $Version hash mismatch: $actual" }

    $file = $null
    $zip = $null
    try {
        $file = [IO.File]::OpenRead($archive)
        $zip = New-Object IO.Compression.ZipArchive($file, [IO.Compression.ZipArchiveMode]::Read)
        Copy-ZipEntry $zip 'miniz.h' $headerPath
        Copy-ZipEntry $zip 'miniz.c' $sourcePath
    } finally {
        if ($zip) { $zip.Dispose() }
        if ($file) { $file.Dispose() }
    }
    [IO.File]::WriteAllText($stampPath, '')
} finally {
    if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
}
