@echo off
setlocal
cd /d "%~dp0"
echo ================================================================
echo   Xiaomi Official Mi Flash Unlock Tool Auto-Downloader
echo ================================================================
echo.
python -c "import hyperunlock_pro as h; h.launch_or_download_mi_unlock(print)"
pause
