@echo off
setlocal
pushd %~dp0

echo Stopping and removing existing containers...
docker compose -f chatgpt/config/docker-compose.yml -f claude/config/docker-compose.yml down

echo Rebuilding and starting ChatGPT and Claude containers...
docker compose -f chatgpt/config/docker-compose.yml up -d --build
if errorlevel 1 goto :error

docker compose -f claude/config/docker-compose.yml up -d --build
if errorlevel 1 goto :error

echo Done! Containers rebuilt.

echo.
echo ===== Notes =====
echo - ChatGPT: MCP on http://localhost:8000, API on http://localhost:8080

echo - Claude: MCP on http://localhost:8001

echo.
popd
endlocal
exit /b 0

:error
echo Build/start failed.
popd
endlocal
exit /b 1