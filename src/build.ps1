$ErrorActionPreference = 'Stop'
$source = $PSScriptRoot
$output = Join-Path (Split-Path $source -Parent) 'bin'
$sdkLine = dotnet --list-sdks | Select-Object -Last 1
if ($sdkLine -notmatch '^(\S+) \[(.+)\]$') {
    throw 'Install the .NET SDK 8 or later.'
}
$compiler = Join-Path (Join-Path $Matches[2] $Matches[1]) 'Roslyn\bincore\csc.dll'
$framework = Join-Path ${env:ProgramFiles(x86)} 'Reference Assemblies\Microsoft\Framework\.NETFramework\v4.8'
if (!(Test-Path (Join-Path $framework 'mscorlib.dll'))) {
    throw 'Install the .NET Framework 4.8 Developer Pack.'
}
New-Item -ItemType Directory -Path $output -Force | Out-Null
$references = 'mscorlib', 'System', 'System.Core', 'System.Drawing', 'System.Windows.Forms'
$arguments = @('/nologo', '/noconfig', '/nostdlib+', '/target:winexe', '/platform:x64', '/optimize+', '/deterministic+',
    "/out:$output\NetScope.exe", "/win32manifest:$source\app.manifest")
$arguments += $references | ForEach-Object { "/reference:$framework\$_.dll" }
$arguments += Get-ChildItem -LiteralPath $source -Filter '*.cs' | ForEach-Object FullName
dotnet $compiler @arguments
if ($LASTEXITCODE -ne 0) { throw 'NetScope build failed.' }
Copy-Item -LiteralPath (Join-Path $source 'App.config') -Destination (Join-Path $output 'NetScope.exe.config')
Write-Host "Built $output\NetScope.exe"
