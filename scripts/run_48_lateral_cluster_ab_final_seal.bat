@echo off
chcp 65001 >nul
setlocal EnableExtensions

set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

set RESULT_ROOT=[RESULT_ROOT]
set SCRIPT=%~dp048_lateral_cluster_ab_final_seal.py

cls
echo ============================================================
echo 48 Lateral Cluster + AB Final Seal
echo ============================================================
echo.
echo Python file:
echo %SCRIPT%
echo.
echo Result root:
echo %RESULT_ROOT%
echo.

where python >nul 2>nul
if errorlevel 1 (
  echo ERROR: python not found in PATH.
  goto END
)

python "%SCRIPT%" "%RESULT_ROOT%"

:END
echo.
echo ============================================================
echo Finished.
echo Output:
echo %RESULT_ROOT%\48_lateral_cluster_ab_final_seal
echo ============================================================
pause
