@echo off
echo ================================================================
echo   Xiaomi / POCO Official ADB ^& Fastboot USB Driver Installer
echo ================================================================
echo.
cd /d "%~dp0"

echo [*] Step 1: Installing Xiaomi ^& Android USB Drivers via Windows PnPUtil...
if exist "%~dp0mi-unlock\driver\win10\android_winusb.inf" (
    pnputil /add-driver "%~dp0mi-unlock\driver\win10\android_winusb.inf" /install
    echo [+] PnPUtil driver registration finished.
) else (
    echo [!] INF file not found at: %~dp0mi-unlock\driver\win10\android_winusb.inf
)

echo.
echo [*] Step 2: Running Xiaomi Official Driver Installer Wizard...
if exist "%~dp0mi-unlock\MiUsbDriver.exe" (
    start "" /wait "%~dp0mi-unlock\MiUsbDriver.exe"
) else if exist "%~dp0mi-unlock\driver_install_64.exe" (
    start "" /wait "%~dp0mi-unlock\driver_install_64.exe"
)

echo.
echo [*] Step 3: Opening Windows Device Manager to verify connection...
start devmgmt.msc

echo.
echo ================================================================
echo [+] USB Driver Installation Complete!
echo     If your phone is in Fastboot mode, it should now appear as:
echo     "Android Bootloader Interface" or "Kedacom USB Device".
echo ================================================================
pause
