---
description: Repository Information Overview
alwaysApply: true
---

# Network Debug MCP Server Information

## Summary
A Model Context Protocol (MCP) server providing network debugging and analysis tools through a Kali Linux container. The server offers various network tools including packet capture, network scanning, DNS tools, connectivity testing, and system monitoring capabilities.

## Structure
- **captures/**: Directory for storing network capture files
- **logs/**: Directory for server logs
- **dockerfile**: Defines the Kali Linux container setup
- **docker-compose.yml**: Container orchestration configuration
- **netdebug_server.py**: Main Python server implementation
- **requirements.txt**: Python dependencies
- **mcp-start.bat**: Windows batch script for starting the MCP server

## Language & Runtime
**Language**: Python 3
**Version**: Python 3.x (Kali Linux)
**Framework**: MCP (Model Context Protocol)
**Package Manager**: pip

## Dependencies
**Main Dependencies**:
- mcp[cli]>=1.2.0: Model Context Protocol framework
- httpx: HTTP client library

**System Dependencies**:
- tcpdump, tshark: Network packet analysis
- nmap, arp-scan: Network scanning
- dnsutils: DNS tools (nslookup, dig)
- net-tools, iproute2: Network configuration tools
- iptables, nftables: Firewall management
- htop, iotop, nethogs: System monitoring

## Build & Installation
```bash
# Build and start the container
docker-compose up -d

# Alternative manual build
docker build -t network-debug-mcp .
docker run -d --name network-debug-mcp --network host --cap-add NET_RAW --cap-add NET_ADMIN network-debug-mcp
```

## Docker
**Dockerfile**: dockerfile
**Image**: Kali Linux (kalilinux/kali-rolling)
**Configuration**: 
- Non-root user (mcpuser) with sudo privileges for network tools
- Network capabilities: NET_RAW, NET_ADMIN, SYS_PTRACE
- Volume mounts for captures and logs
- Environment variables for configuration

## Environment Variables
- MCP_SERVER_NAME: Server identification (default: "network-debug")
- MCP_SERVER_VERSION: Version string (default: "1.0.0")
- CAPTURE_DIR: Directory for capture files (default: "/home/netdebug/captures")
- MAX_CAPTURE_SIZE: Maximum capture file size (default: "100M")
- DEFAULT_TIMEOUT: Default command timeout in seconds (default: "30")

## Security Features
- Runs as non-root user with minimal required capabilities
- Input sanitization to prevent command injection
- Timeout limits on all commands
- Limited output sizes to prevent resource exhaustion
- Restricted command parameters to safe values only

## Available Tools
The server provides various network tools as MCP functions:
- Network Capture: tcpdump_capture, process_network_usage
- Network Analysis: nmap_scan, netstat_connections, ss_connections
- DNS Tools: nslookup_query, dig_query
- Connectivity Testing: ping_host, traceroute_host, curl_test
- System Information: ip_route_show, ip_addr_show, iptables_list