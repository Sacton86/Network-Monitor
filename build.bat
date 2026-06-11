@echo off
echo Installing dependencies...
pip install psutil pystray Pillow matplotlib pyinstaller

echo.
echo Building NetWatch.exe...
pyinstaller ^
    --onefile ^
    --windowed ^
    --name NetWatch ^
    --uac-admin ^
    --hidden-import matplotlib.backends.backend_tkagg ^
    --hidden-import matplotlib.figure ^
    --hidden-import pystray._win32 ^
    --collect-data matplotlib ^
    main.py

echo.
if exist dist\NetWatch.exe (
    echo  SUCCESS: dist\NetWatch.exe
) else (
    echo  BUILD FAILED - check output above
)
pause
