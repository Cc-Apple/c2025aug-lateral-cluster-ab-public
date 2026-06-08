@echo off
setlocal
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

echo ============================================================
echo 47 Normal / Control Stress Test Review
echo ============================================================

set "RESULT_ROOT=[RESULT_ROOT]"
set "PYFILE=%~dp047_normal_control_stress_test_review.py"

if not exist "%PYFILE%" (
  echo ERROR: Python file not found:
  echo %PYFILE%
  pause
  exit /b 1
)

python "%PYFILE%" "%RESULT_ROOT%"

echo.
echo ============================================================
echo Finished.
echo Output:
echo %RESULT_ROOT%\47_normal_control_stress_test_review
echo ============================================================
pause
endlocal
