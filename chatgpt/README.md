# Network Debug MCP for ChatGPT

This directory contains the configuration files for running the Network Debug MCP server as a ChatGPT plugin.

## Overview

ChatGPT plugins use the OpenAPI specification to interact with external services. This configuration sets up the server to work as a ChatGPT plugin, providing network debugging tools through a REST API.

## Getting Started

1. Navigate to the chatgpt directory:
   ```
   cd chatgpt
   ```

2. Start the server:
   ```
   docker-compose -f config/docker-compose.yml up -d
   ```

3. The API server will be available at `http://localhost:8080`
4. The MCP server will be available at `http://localhost:8000`

## Configuration

The ChatGPT-specific configuration includes:

- Container name: `network-debug-mcp-chatgpt`
- Port mappings: 
  - `8000:8000` (MCP server)
  - `8080:8080` (API server)
- API title: `Network Debug MCP for ChatGPT`
- API description: `A Model Context Protocol (MCP) server providing network debugging and analysis tools for ChatGPT integration.`

## Deploying as a ChatGPT Plugin

To deploy this as a ChatGPT plugin:

1. Host the server on a publicly accessible domain with HTTPS
2. Update the URLs in `config/ai-plugin.json` and `config/openapi.yaml` to point to your domain
3. Create a `.well-known` directory on your server and place the `ai-plugin.json` file there
4. Host the `openapi.yaml` file at the URL specified in the `ai-plugin.json` file
5. Register your plugin with ChatGPT by following the instructions in the ChatGPT plugin documentation

## Available API Endpoints

The following API endpoints are available:

- `/nmap_scan`: Perform network scanning with nmap
- `/tcpdump_capture`: Capture network packets using tcpdump
- `/ping_host`: Ping a host to test connectivity
- `/traceroute_host`: Trace route to a host
- `/ip_addr_show`: Show network interfaces using ip addr
- `/ip_route_show`: Show routing table using ip route
- `/nslookup_query`: Perform DNS lookup using nslookup
- `/dig_query`: Perform DNS lookup using dig

Each endpoint accepts a JSON payload with parameters specific to the tool.