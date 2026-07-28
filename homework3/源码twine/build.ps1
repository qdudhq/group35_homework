# build_twine.ps1
 = "C:\Program Files\Microsoft Visual Studio2\Preview"
if (-not (Test-Path )) {  = "C:\Program Files\Microsoft Visual Studio2\Community" }
if (-not (Test-Path )) {  = "C:\Program Files\Microsoft Visual Studio2\Professional" }
& "\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64 -SkipAutomaticLocation
 = @("twine_ref.c","twine_ttable.c","twine_shuffle.c","twine_bitslice.c","twine_avx2.c","twine_modes.c","twine_main.c")
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
cl.exe  /Fe:twine_bench.exe /link
if ( -eq 0) { Write-Host "Build OK"; & .	wine_bench.exe }
