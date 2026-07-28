# build_gift.ps1
 = "C:\Program Files\Microsoft Visual Studio2\Preview"
if (-not (Test-Path )) {  = "C:\Program Files\Microsoft Visual Studio2\Community" }
if (-not (Test-Path )) {  = "C:\Program Files\Microsoft Visual Studio2\Professional" }
& "\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64 -SkipAutomaticLocation
 = @("gift_ref.c","gift_ttable.c","gift_shuffle.c","gift_bitslice.c","gift_avx2.c","gift_modes.c","gift_main.c")
 = @()
 = "/nologo /O2 /arch:AVX2 /W3 /D_CRT_SECURE_NO_WARNINGS /std:c11"
foreach ( in ) {
     =  -replace "\.c$",".obj"
    Write-Host "Compiling "
    cl.exe /c   /Fo:
    if ( -ne 0) { Write-Host "ERROR:  failed"; exit 1 }
     += 
}
Write-Host "Linking..."
cl.exe  /Fe:gift_bench.exe /link
if ( -eq 0) { Write-Host "Build OK"; & .\gift_bench.exe }
