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
echo [RESULT_ROOT]

echo.
echo Running 42...
python "%~dp042_trial_ab_cohort_source_review.py" "[RESULT_ROOT]"

echo.
echo ============================================================
echo Finished.
echo Output:
echo [RESULT_ROOT]\42_trial_ab_cohort_source_review
echo ============================================================
pause
