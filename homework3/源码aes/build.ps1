# build.ps1 - Build script for AES optimization project
# Uses Visual Studio 2022 MSVC compiler

$ProjectDir = "D:\360MoveData\Users\ygd06\Desktop\35组 作业三"
Set-Location $ProjectDir

# Try to find VS Dev Shell
$VsPath = "C:\Program Files\Microsoft Visual Studio\2022\Preview"
if (-not (Test-Path $VsPath)) {
    $VsPath = "C:\Program Files\Microsoft Visual Studio\2022\Community"
}
if (-not (Test-Path $VsPath)) {
    $VsPath = "C:\Program Files\Microsoft Visual Studio\2022\Professional"
}

Write-Host "Using VS: $VsPath"

# Launch VS Dev Shell and compile
& "$VsPath\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64 -SkipAutomaticLocation

$Sources = @("aes_ref.c", "aes_ttable.c", "aes_shuffle.c", "aes_ni.c", "modes.c", "main.c")
$ObjFiles = @()

$CFlags = "/nologo /O2 /arch:AVX2 /W3 /D_CRT_SECURE_NO_WARNINGS"

foreach ($src in $Sources) {
    $obj = $src -replace '\.c$', '.obj'
    Write-Host "Compiling $src -> $obj"
    cl.exe /c $CFlags $src /Fo:$obj
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Compilation failed for $src"
        exit 1
    }
    $ObjFiles += $obj
}

Write-Host "Linking..."
cl.exe $ObjFiles /Fe:aes_bench.exe /link

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n========================================"
    Write-Host "  Build successful! aes_bench.exe"
    Write-Host "========================================"
    Write-Host "`nRunning benchmark...`n"
    & .\aes_bench.exe
} else {
    Write-Host "Link failed!"
}
