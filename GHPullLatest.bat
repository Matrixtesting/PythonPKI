@echo off
setlocal
set REMOTE_NAME=origin
set BRANCH_NAME=main
git pull %REMOTE_NAME% %BRANCH_NAME%
endlocal
pause
