RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 C:\DriverTest\Drivers\naGuard.inf
pause
fltmc load naGuard
pause
sc start naGuard
pause