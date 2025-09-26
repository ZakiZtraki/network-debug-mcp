# Network Debug MCP Server

A Model Context Protocol (MCP) server providing network debugging and analysis tools through a Kali Linux container. This repository is structured to support two different use cases:

1. **ChatGPT Integration**: Run the server as a ChatGPT plugin using the OpenAPI specification
2. **Claude Integration**: Run the server as a native MCP server for Claude

## Repository Structure

```
KaliMCP/
├── captures/                  # Directory for storing network capture files
├── logs/                      # Directory for server logs
├── chatgpt/                   # ChatGPT-specific configuration
│   ├── config/                # Configuration files for ChatGPT
│   │   ├── ai-plugin.json     # ChatGPT plugin manifest
│   │   ├── docker-compose.yml # Docker Compose for ChatGPT setup
│   │   └── openapi.yaml       # OpenAPI specification for ChatGPT
│   └── README.md              # ChatGPT-specific documentation
├── claude/                    # Claude-specific configuration
│   ├── config/                # Configuration files for Claude
│   │   └── docker-compose.yml # Docker Compose for Claude setup
│   └── README.md              # Claude-specific documentation
└── common/                    # Shared components
    ├── docker/                # Docker configuration
    │   ├── dockerfile         # Dockerfile for building the container
    │   └── docker-compose.base.yml # Base Docker Compose configuration
    └── server/                # Server implementation
        ├── api_server.py      # REST API server for ChatGPT
        └── netdebug_server.py # MCP server implementation
```

## Getting Started

### Prerequisites

- Docker and Docker Compose installed
- Git (for cloning the repository)

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/network-debug-mcp.git
   cd network-debug-mcp
   ```

2. Choose your integration:

   **For ChatGPT:**
   - Recommended: run start-chatgpt.bat from the repo root.
   - Or:
   ```
   docker compose -f chatgpt/config/docker-compose.yml up -d
   ```

   **For Claude:**
   - Recommended: run start-claude.bat from the repo root.
   - Or:
   ```
   docker compose -f claude/config/docker-compose.yml up -d
   ```

## Configuration: Domain, URLs, and LAN

- Public FQDN: Replace netdebug.zakitraki.com with your own domain where noted below.
- ChatGPT plugin manifest (.well-known/ai-plugin.json):
  - api.url: https://<FQDN>/config/openapi.yaml
  - logo_url: https://<FQDN>/config/logo.png
  - legal_info_url: https://<FQDN>/config/legal
- OpenAPI (chatgpt/config/openapi.yaml):
  - servers[0].url: https://<FQDN>
- TLS: Ensure HTTPS is valid at the chosen FQDN.
- LAN scope default: Use 10.10.0.0/16. Update any examples accordingly.


## Features

- **Packet Capture**: tcpdump integration for network packet analysis
- **Network Scanning**: nmap for port and service discovery
- **Connection Monitoring**: netstat and ss for active connections
- **DNS Tools**: nslookup and dig for DNS resolution testing
- **Connectivity Testing**: ping and traceroute
- **System Monitoring**: htop, iotop, and nethogs for resource usage
- **Routing Analysis**: ip route and ip addr commands
- **Firewall Rules**: iptables listing and analysis
- **HTTP Testing**: curl for web connectivity testing

## Security Features

- Runs as non-root user with minimal required capabilities
- Input sanitization to prevent command injection
- Timeout limits on all commands
- Limited output sizes to prevent resource exhaustion
- Restricted command parameters to safe values only

## Available Tools

### Network Capture
- `tcpdump_capture`: Capture packets on specified interface
- `process_network_usage`: Monitor network usage by process

### Network Analysis
- `nmap_scan`: Port and service scanning
- `netstat_connections`: List active network connections
- `ss_connections`: Show socket statistics
- `network_interfaces`: List available network interfaces

### DNS Tools
- `nslookup_query`: DNS lookups with various record types
- `dig_query`: Advanced DNS queries with custom servers

### Connectivity Testing
- `ping_host`: ICMP ping connectivity tests
- `traceroute_host`: Network route tracing
- `curl_test`: HTTP/HTTPS connectivity testing

### System Information
- `ip_route_show`: Display routing tables
- `ip_addr_show`: Show interface configurations
- `iptables_list`: List firewall rules
- `system_resource_usage`: System resource monitoring
- `io_statistics`: I/O performance statistics

## Environment Variables

- `MCP_SERVER_NAME`: Server identification (default: "network-debug")
- `MCP_SERVER_VERSION`: Version string (default: "1.0.0")
- `CAPTURE_DIR`: Directory for capture files (default: "/home/netdebug/captures")
- `MAX_CAPTURE_SIZE`: Maximum capture file size (default: "100M")
- `DEFAULT_TIMEOUT`: Default command timeout in seconds (default: "30")

## Usage

### ChatGPT (Plugin)
- Ensure the server is reachable at https://<FQDN>
- In ChatGPT, install the plugin by URL: https://<FQDN>/.well-known/ai-plugin.json
- Example prompts:
  - "Scan 10.10.0.0/24 for open SSH and HTTP ports."
  - "Capture 60 seconds of traffic on interface eth0 and save it."
  - "List active connections to 10.10.1.5."
  - "Run traceroute to 8.8.8.8 and summarize the hops."
  - "Check DNS resolution for api.example.com using 1.1.1.1."
  - "Show firewall rules and highlight anything blocking 443/tcp."

### Claude (Native MCP)
- Start the MCP server: `docker compose -f claude/config/docker-compose.yml up -d`
- In Claude, enable/connect to the "network-debug" MCP server via MCP settings.
- Example prompts:
  - "Show interface configurations and current routes."
  - "Run nmap on 10.10.0.1 with a SYN scan for ports 22,80,443."
  - "Ping 1.1.1.1 and report packet loss and latency."
  - "Perform a DNS lookup for api.example.com using server 8.8.8.8."

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.