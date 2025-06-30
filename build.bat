@echo off
echo Cleaning old build files...
rmdir /s /q dist
rmdir /s /q build
del /q /f gui.spec

echo Building new version...
pyinstaller --noconsole --onefile --add-data "dgdi_logo.png;." gui.py

echo.
echo ✅ Build complete!
pause
