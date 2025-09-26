# Network Debug MCP for Claude

This directory contains the configuration files for running the Network Debug MCP server with Claude.

## Overview

Claude can directly connect to MCP servers using the native MCP protocol. This configuration sets up the server to work specifically with Claude's MCP integration.

## Getting Started

1. Navigate to the claude directory:
   ```
   cd claude
   ```

2. Start the server:
   ```
   docker-compose -f config/docker-compose.yml up -d
   ```

3. The server will be available at `http://localhost:8001`

## Configuration

The Claude-specific configuration includes:

- Container name: `network-debug-mcp-claude`
- Port mapping: `8001:8000` (to avoid conflicts with the ChatGPT instance)
- MCP transport: `sse` (Server-Sent Events)
- Server name: `network-debug-claude`

## Using with Claude

To use this MCP server with Claude:

1. Ensure the server is running and accessible from the internet (if using Claude via API)
2. Configure Claude to connect to your MCP server URL
3. Use Claude's interface to interact with the network debugging tools

## Available Tools

The following network debugging tools are available:

- `tcpdump_capture`: Capture network packets
- `nmap_scan`: Scan networks and hosts
- `ping_host`: Test connectivity to hosts
- `traceroute_host`: Trace network routes
- `ip_addr_show`: Show network interfaces
- `ip_route_show`: Show routing tables
- `nslookup_query`: Perform DNS lookups with nslookup
- `dig_query`: Perform DNS lookups with dig
- `curl_test`: Test HTTP/HTTPS connectivity
- `process_network_usage`: Show processes with network connections
- `iptables_list`: List firewall rules