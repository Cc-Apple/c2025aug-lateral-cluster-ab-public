@echo off
chcp 65001 >nul
setlocal
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

echo ============================================================
echo 44 Backup / Manifest Inheritance Review
echo ============================================================

set RESULT_ROOT=C:\Users\Administrator\Desktop\Result
set SCRIPT_DIR=%~dp0

python "%SCRIPT_DIR%44_backup_manifest_inheritance_review.py" --result-root "%RESULT_ROOT%"

echo.
echo ============================================================
echo Finished.
echo Output:
echo %RESULT_ROOT%\44_backup_manifest_inheritance_review
echo ============================================================
pause
