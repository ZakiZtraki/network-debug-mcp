@echo off
setlocal
pushd %~dp0

echo Starting Network Debug MCP Server for Claude...

docker compose -f claude/config/docker-compose.yml up -d

if errorlevel 1 (
  echo Failed to start Claude MCP server.
  popd
  endlocal
  exit /b 1
)

echo Server started!
echo MCP (SSE): http://localhost:8001

popd
endlocal