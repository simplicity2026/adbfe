:: COMMENT: this batch file compiles adbfe1.cpp to adbfe1.exe (32bit) using mingw32...
:: i used (x86): https://github.com/brechtsanders/winlibs_mingw/releases/download/14.2.0posix-12.0.0-ucrt-r3/winlibs-i686-posix-dwarf-gcc-14.2.0-llvm-19.1.7-mingw-w64ucrt-12.0.0-r3.7z
:: you can also use (x64): https://github.com/brechtsanders/winlibs_mingw/releases/download/14.2.0posix-12.0.0-ucrt-r3/winlibs-x86_64-posix-seh-gcc-14.2.0-llvm-19.1.7-mingw-w64ucrt-12.0.0-r3.7z
:: ///
@cls
D:\20251216\mingw32\bin\windres.exe D:\20251216\ADBFE1\adbfe1.rc -O coff -o D:\20251216\ADBFE1\adbfe1.res
taskkill /f /IM adbfe1.exe
D:\20251216\mingw32\bin\g++.exe D:\20251216\ADBFE1\adbfe1.cpp D:\20251216\ADBFE1\adbfe1.res -mwindows -static -lcomctl32 -lshell32 -ladvapi32 -luxtheme -lpsapi -lshlwapi -Os -s -o D:\20251216\ADBFE1\adbfe1.exe
start /b D:\20251216\ADBFE1\adbfe1.exe
taskkill /IM adbfe1_upx.exe
@del D:\20251216\ADBFE1\adbfe1_upx.exe
D:\20251216\ADBFE1\upx.exe -9 D:\20251216\ADBFE1\adbfe1.exe -o D:\20251216\ADBFE1\adbfe1_upx.exe
::timeout /t 3
::@cmd