@echo off
setlocal
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

echo ============================================================
echo 45 Proximity vs Cloud Separation Review
echo ============================================================

set SCRIPT=%~dp045_proximity_vs_cloud_separation_review.py
set OUT=[RESULT_ROOT]\45_proximity_vs_cloud_separation_review

python "%SCRIPT%" ^
  --in39b "[RESULT_ROOT]\39b_rawlog_cluster_trial_audit" ^
  --in40b "[RESULT_ROOT]\40b_c2025aug_39a39b_cross_strict" ^
  --in43 "[RESULT_ROOT]\43_trust_graph_lineage_review" ^
  --in44 "[RESULT_ROOT]\44_backup_manifest_inheritance_review" ^
  --out "%OUT%"

echo.
echo ============================================================
echo Finished.
echo Output:
echo %OUT%
echo ============================================================
pause
