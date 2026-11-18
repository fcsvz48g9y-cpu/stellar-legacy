@echo off
cd /d "%~dp0"
start "Stellar Legacy server" cmd /k "node server.js"
timeout /t 2 /nobreak >nul
start "" http://localhost:3000
