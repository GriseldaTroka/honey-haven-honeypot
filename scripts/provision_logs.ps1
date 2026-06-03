Param()
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$root = Resolve-Path "$root\.."
New-Item -ItemType Directory -Force -Path "$root\logs\cowrie" | Out-Null
New-Item -ItemType Directory -Force -Path "$root\logs\dionaea" | Out-Null
New-Item -ItemType Directory -Force -Path "$root\logs\conpot" | Out-Null
New-Item -ItemType Directory -Force -Path "$root\logs\web" | Out-Null
Write-Output "Created logs folders under $($root)\logs"
