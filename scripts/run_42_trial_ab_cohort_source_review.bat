@echo off
setlocal
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

echo ============================================================
echo 42 Trial / A-B / Cohort Source Review
echo ============================================================

echo.
echo Input root:
echo C:\Users\Administrator\Desktop\Result

echo.
echo Running 42...
python "%~dp042_trial_ab_cohort_source_review.py" "C:\Users\Administrator\Desktop\Result"

echo.
echo ============================================================
echo Finished.
echo Output:
echo C:\Users\Administrator\Desktop\Result\42_trial_ab_cohort_source_review
echo ============================================================
pause
