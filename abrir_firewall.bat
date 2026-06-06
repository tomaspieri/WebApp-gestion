@echo off
echo Abriendo puerto 3000 en el firewall...
netsh advfirewall firewall add rule name="Gestion de Ventas Puerto 3000" protocol=TCP dir=in localport=3000 action=allow
echo.
echo Listo! Ya podés acceder desde el celular.
pause
