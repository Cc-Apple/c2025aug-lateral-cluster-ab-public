@echo off
setlocal
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

set RESULT_ROOT=[RESULT_ROOT]
set SCRIPT=%~dp042b_triald_direct_only_source_time_review.py

if not exist "%SCRIPT%" (
  echo Python script not found: %SCRIPT%
  pause
  exit /b 1
)

echo ============================================================
echo 42b triald direct only source-time review
echo ============================================================
echo Input root:
echo %RESULT_ROOT%
echo.

python "%SCRIPT%" "%RESULT_ROOT%"

if errorlevel 1 (
  echo.
  echo 42b failed.
  pause
  exit /b 1
)

echo.
echo Finished.
echo Output:
echo %RESULT_ROOT%\42b_triald_direct_only_source_time_review
echo ============================================================
pause
