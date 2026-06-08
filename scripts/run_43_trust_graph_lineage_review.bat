@echo off
setlocal
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

echo ============================================================
echo 43 Trust Graph Lineage Review
echo ============================================================

set BASE=C:\Users\Administrator\Desktop\Result
set SCRIPT=%~dp043_trust_graph_lineage_review.py

if not exist "%SCRIPT%" (
  echo Python file not found: %SCRIPT%
  pause
  exit /b 1
)

python "%SCRIPT%" --base "%BASE%"

echo.
echo ============================================================
echo Finished.
echo Output:
echo %BASE%\43_trust_graph_lineage_review
echo ============================================================
pause
