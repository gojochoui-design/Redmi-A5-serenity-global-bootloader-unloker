@echo off
title SerenityUnlock - Redmi A5 4G (serenity)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0SerenityUnlock.ps1"
if errorlevel 1 (
  echo.
  echo SerenityUnlock termino con error. Revisa el mensaje anterior.
  pause
)
