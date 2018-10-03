sc stop naGuard
pause
fltmc unload naGuard
pause
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultUninstall 132 C:\DriverTest\Drivers\naGuard.inf
pause