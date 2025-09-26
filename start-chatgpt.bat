@echo off
setlocal
pushd %~dp0

echo Starting Network Debug MCP Server for ChatGPT...

docker compose -f chatgpt/config/docker-compose.yml up -d

if errorlevel 1 (
  echo Failed to start ChatGPT MCP server.
  popd
  endlocal
  exit /b 1
)

echo Server started!
echo API: http://localhost:8080
echo MCP (SSE): http://localhost:8000

popd
endlocal