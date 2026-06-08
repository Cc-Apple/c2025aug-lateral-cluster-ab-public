@echo off
setlocal
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

echo ============================================================
echo 45 Proximity vs Cloud Separation Review
echo ============================================================

set SCRIPT=%~dp045_proximity_vs_cloud_separation_review.py
set OUT=C:\Users\Administrator\Desktop\Result\45_proximity_vs_cloud_separation_review

python "%SCRIPT%" ^
  --in39b "C:\Users\Administrator\Desktop\Result\39b_rawlog_cluster_trial_audit" ^
  --in40b "C:\Users\Administrator\Desktop\Result\40b_c2025aug_39a39b_cross_strict" ^
  --in43 "C:\Users\Administrator\Desktop\Result\43_trust_graph_lineage_review" ^
  --in44 "C:\Users\Administrator\Desktop\Result\44_backup_manifest_inheritance_review" ^
  --out "%OUT%"

echo.
echo ============================================================
echo Finished.
echo Output:
echo %OUT%
echo ============================================================
pause
