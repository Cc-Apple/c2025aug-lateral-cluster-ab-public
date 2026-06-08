@echo off
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

set IN_DIR=C:\Users\Administrator\Desktop\Result\39b_rawlog_cluster_trial_audit
set OUT_DIR=C:\Users\Administrator\Desktop\Result\40_c2025aug_39b_strict_review

python "%~dp040_c2025aug_39b_strict_review.py" "%IN_DIR%" "%OUT_DIR%"

echo.
echo Finished.
echo Output:
echo %OUT_DIR%
pause
