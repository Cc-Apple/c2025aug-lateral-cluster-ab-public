@echo off
setlocal
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

echo ============================================================
echo 46 Evidence Preservation / Suppression Review
echo ============================================================

set SCRIPT=%~dp046_evidence_preservation_suppression_review.py
set IN39B=[RESULT_ROOT]\39b_rawlog_cluster_trial_audit
set IN40B=[RESULT_ROOT]\40b_c2025aug_39a39b_cross_strict
set IN43=[RESULT_ROOT]\43_trust_graph_lineage_review
set IN44=[RESULT_ROOT]\44_backup_manifest_inheritance_review
set IN45=[RESULT_ROOT]\45_proximity_vs_cloud_separation_review
set OUT=[RESULT_ROOT]\46_evidence_preservation_suppression_review

python "%SCRIPT%" --in39b "%IN39B%" --in40b "%IN40B%" --in43 "%IN43%" --in44 "%IN44%" --in45 "%IN45%" --out "%OUT%"

echo.
echo ============================================================
echo Finished.
echo Output:
echo %OUT%
echo ============================================================
pause
