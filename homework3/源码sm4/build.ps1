# build_sm4.ps1 - Build SM4 project
$VsPath = "C:\Program Files\Microsoft Visual Studio2\Preview"
if (-not (Test-Path $VsPath)) { $VsPath = "C:\Program Files\Microsoft Visual Studio2\Community" }
if (-not (Test-Path $VsPath)) { $VsPath = "C:\Program Files\Microsoft Visual Studio2\Professional" }
& "$VsPath\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64 -SkipAutomaticLocation
$srcs = @("sm4_ref.c","sm4_ttable.c","sm4_shuffle.c","sm4_ni.c","sm4_avx2.c","sm4_modes.c","sm4_main.c")
$objs = @()
$cflags = "/nologo /O2 /arch:AVX2 /W3 /D_CRT_SECURE_NO_WARNINGS /std:c11"
foreach ($s in $srcs) {
    $o = $s -replace "\.c$",".obj"
    Write-Host "Compiling $s"
    cl.exe /c $cflags $s /Fo:$o
    if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: $s failed"; exit 1 }
    $objs += $o
}
Write-Host "Linking..."
cl.exe $objs /Fe:sm4_bench.exe /link
if ($LASTEXITCODE -eq 0) { Write-Host "Build OK"; & .\sm4_bench.exe }
