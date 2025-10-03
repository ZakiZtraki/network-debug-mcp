import asyncio
import os
import sys
import logging
import subprocess
import re
import shlex
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from mcp.server.fastmcp import FastMCP


# Configure enhanced logging with rotation
# Ensure log directory exists inside the container
log_dir = os.getenv("LOG_DIR", "/app/logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "server.log")

# Enhanced formatter with more details
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Stream handler (stderr → docker logs) - for container logs
stream_handler = logging.StreamHandler(sys.stderr)
stream_handler.setLevel(logging.INFO)
stream_handler.setFormatter(formatter)

# Rotating file handler (prevents log files from growing too large)
file_handler = RotatingFileHandler(
    log_file,
    maxBytes=10*1024*1024,  # 10MB per log file
    backupCount=5,          # Keep 5 backup files
    encoding='utf-8'
)
file_handler.setLevel(logging.DEBUG)  # More detailed logging to file
file_handler.setFormatter(formatter)

# Root logger configuration
logging.basicConfig(
    level=logging.DEBUG,
    handlers=[stream_handler, file_handler],
    force=True  # Override any existing configuration
)

logger = logging.getLogger("netdebug-server")

# Create child loggers for different components
cmd_logger = logging.getLogger("netdebug-server.commands")
security_logger = logging.getLogger("netdebug-server.security")
perf_logger = logging.getLogger("netdebug-server.performance")

# Tool usage tracking
tool_usage = {}

# Pre-build SSE Cache-Control header to avoid recalculating
DEFAULT_SSE_HEADERS = {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Expires": "0",
    "X-Accel-Buffering": "no",
}

def log_tool_usage(tool_name, params=None):
    """Track tool usage for analytics"""
    if tool_name not in tool_usage:
        tool_usage[tool_name] = 0
    tool_usage[tool_name] += 1

    logger.info(f"Tool called: {tool_name} (usage count: {tool_usage[tool_name]})")
    if params:
        logger.debug(f"Tool parameters: {params}")

    # Log to performance logger for analytics
    perf_logger.info(f"Tool usage: {tool_name}")

# Initialize MCP server
mcp = FastMCP(os.getenv("MCP_SERVER_NAME", "netdebug"))

# Environment configuration with logging
logger.info("Loading server configuration from environment variables")

CAPTURE_DIR = os.getenv("CAPTURE_DIR", "/home/mcpuser/captures")
MAX_CAPTURE_SIZE = os.getenv("MAX_CAPTURE_SIZE", "100M")
DEFAULT_TIMEOUT = int(os.getenv("DEFAULT_TIMEOUT", "30"))
MAX_TIMEOUT = int(os.environ.get("NETDEBUG_MAX_TIMEOUT", "30"))
DEFAULT_COUNT = int(os.environ.get("NETDEBUG_DEFAULT_COUNT", "10"))
DEFAULT_INTERFACE = os.environ.get("NETDEBUG_INTERFACE", "auto")

logger.info(f"Configuration loaded: CAPTURE_DIR={CAPTURE_DIR}, MAX_CAPTURE_SIZE={MAX_CAPTURE_SIZE}")
logger.info(f"Timeouts: DEFAULT_TIMEOUT={DEFAULT_TIMEOUT}s, MAX_TIMEOUT={MAX_TIMEOUT}s")
logger.info(f"Defaults: DEFAULT_COUNT={DEFAULT_COUNT}, DEFAULT_INTERFACE={DEFAULT_INTERFACE}")

# Ensure capture directory exists
os.makedirs(CAPTURE_DIR, exist_ok=True)
logger.info(f"Capture directory ready: {CAPTURE_DIR}")

# === UTILITY FUNCTIONS ===

def detect_primary_interface():
    """Auto-detect the primary network interface"""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0 and result.stdout:
            # Extract interface from default route
            parts = result.stdout.split()
            if 'dev' in parts:
                idx = parts.index('dev')
                return parts[idx + 1]
    except:
        pass
    return "eth0"  # fallback
# Update the configuration section based on environment variables
if DEFAULT_INTERFACE == "auto":
    DEFAULT_INTERFACE = detect_primary_interface()

def sanitize_input(value):
    """Sanitize input to prevent command injection"""
    if not isinstance(value, str):
        security_logger.warning(f"Non-string input received: {type(value)}")
        return ""

    original_length = len(value)
    # Remove dangerous characters and limit length
    sanitized = re.sub(r'[;&|`$(){}[\]<>]', '', value)
    sanitized = sanitized[:200]

    if len(sanitized) != original_length:
        security_logger.info(f"Input sanitized: original length {original_length}, sanitized length {len(sanitized)}")

    return sanitized

def sanitize_ip(ip):
    """Validate and sanitize IP addresses"""
    if not ip:
        return ""

    # Basic IP validation
    ip_pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, ip):
        parts = ip.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            security_logger.debug(f"Valid IP address: {ip}")
            return ip

    security_logger.warning(f"Invalid IP address rejected: {ip}")
    return ""

def validate_domain(domain):
    """Validate domain name format"""
    if not domain:
        return False

    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]$'
    is_valid = bool(re.match(pattern, domain))

    if not is_valid:
        security_logger.warning(f"Invalid domain name rejected: {domain}")

    return is_valid

def sanitize_port(port):
    """Validate and sanitize port numbers"""
    if not port:
        return ""

    try:
        port_num = int(port)
        if 1 <= port_num <= 65535:
            security_logger.debug(f"Valid port number: {port_num}")
            return str(port_num)
        else:
            security_logger.warning(f"Port number out of range: {port_num}")
    except ValueError:
        security_logger.warning(f"Invalid port format: {port}")

    return ""

def run_command_sync(cmd, timeout=None):
    """Execute command synchronously with enhanced logging and performance tracking"""
    start_time = time.time()
    cmd_str = ' '.join(cmd)

    try:
        if timeout is None:
            timeout = DEFAULT_TIMEOUT

        cmd_logger.info(f"Executing command: {cmd_str[:100]}{'...' if len(cmd_str) > 100 else ''}")
        cmd_logger.debug(f"Full command: {cmd_str}")
        cmd_logger.debug(f"Timeout: {timeout}s")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        execution_time = time.time() - start_time
        perf_logger.info(f"Command completed in {execution_time:.2f}s: {cmd[0]}")

        if result.returncode == 0:
            cmd_logger.info(f"Command succeeded: {cmd[0]} (exit code: 0)")
            if result.stdout:
                cmd_logger.debug(f"Command output length: {len(result.stdout)} characters")
            return result.stdout if result.stdout else "Command completed successfully"
        else:
            error_msg = result.stderr or f"Command failed with exit code {result.returncode}"
            cmd_logger.warning(f"Command failed: {cmd[0]} (exit code: {result.returncode})")
            if result.stderr:
                cmd_logger.warning(f"Command stderr: {result.stderr[:200]}{'...' if len(result.stderr) > 200 else ''}")
            return f"Command failed: {error_msg}"

    except subprocess.TimeoutExpired:
        execution_time = time.time() - start_time
        cmd_logger.error(f"Command timed out after {timeout}s: {cmd[0]}")
        perf_logger.warning(f"Command timeout: {cmd[0]} ({execution_time:.2f}s)")
        return f"Command timed out after {timeout} seconds"
    except Exception as e:
        execution_time = time.time() - start_time
        cmd_logger.error(f"Command execution error: {str(e)} - Command: {cmd[0]}")
        cmd_logger.exception("Full exception details:")
        perf_logger.error(f"Command exception: {cmd[0]} ({execution_time:.2f}s)")
        return f"Error executing command: {str(e)}"

# === MCP TOOL FUNCTIONS ===

@mcp.tool()
def tcpdump_capture(interface: str = "eth0", count: str = "10", filter_expr: str = ""):
    """Capture network packets using tcpdump"""
    log_tool_usage("tcpdump_capture", {"interface": interface, "count": count, "filter": filter_expr})
    logger.info(f"tcpdump_capture called: interface={interface}, count={count}, filter={filter_expr}")

    interface = sanitize_input(interface)
    count = sanitize_input(count)
    filter_expr = sanitize_input(filter_expr)

    if not interface:
        interface = "eth0"
        logger.info("Using default interface: eth0")

    try:
        count_num = int(count) if count else 10
        count_num = min(count_num, 1000)  # Limit captures
        logger.info(f"Packet capture count set to: {count_num}")
    except ValueError:
        count_num = 10
        logger.warning("Invalid count parameter, using default: 10")

    cmd = ["tcpdump", "-i", interface, "-c", str(count_num), "-n"]
    if filter_expr:
        cmd.extend(filter_expr.split())
        logger.info(f"Applied filter expression: {filter_expr}")

    security_logger.info(f"Network capture initiated on interface {interface} with {count_num} packets")
    result = run_command_sync(cmd, timeout=60)
    logger.info(f"tcpdump_capture completed for interface {interface}")

    return f"TCPDump capture on {interface} (count: {count_num}):\n{result}"

@mcp.tool()
def arp_scan_network(network: str = "") -> str:
    """Scan local network for hosts using ARP - provide network like '10.10.2.0/24'."""
    logger.info(f"Executing arp_scan_network with network={network}")
    
    if not network.strip():
        return "❌ Error: Network range is required (e.g., 10.10.2.0/24)"
    
    network = sanitize_input(network)
    
    # Validate network format
    pattern = r'^(?:(?:\d{1,3}\.){3})(?:\d{1})\/\d{1,2}$'
    if not re.match(pattern, network):
        return "❌ Error: Invalid network format. Use CIDR notation (e.g., 10.10.2.0/24)"
    
    try:
        cmd = ["arp-scan", "network", network]
        result = run_command_sync(cmd, timeout=60)
        return f"🔍 ARP Scan Results for {network}:\n{result}"
    except Exception as e:
        logger.error(f"Error: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
def nmap_scan(target: str = "", scan_type: str = "-sS", ports: str = ""):
    """Perform network scanning with nmap (full access as root)"""
    log_tool_usage("nmap_scan", {"target": target, "scan_type": scan_type, "ports": ports})
    logger.info(f"nmap_scan called: target={target}, scan_type={scan_type}, ports={ports}")

    target = sanitize_input(target)
    scan_type = sanitize_input(scan_type)
    ports = sanitize_input(ports)

    if not target:
        logger.warning("nmap_scan: No target specified")
        return "Error: Target IP or hostname required"

    if not (sanitize_ip(target) or re.match(r'^[a-zA-Z0-9.-/]+$', target)):
        logger.warning(f"nmap_scan: Invalid target format: {target}")
        return "Error: Invalid target format"

    cmd = ["nmap"]

    # All scan types are available as root
    allowed_scan_types = ["-sS", "-sT", "-sU", "-sA", "-sF", "-sN", "-sX", "-sn"]
    if scan_type in allowed_scan_types:
        cmd.append(scan_type)
        logger.info(f"nmap_scan: Using scan type {scan_type}")
    else:
        cmd.append("-sS")  # Default to SYN scan
        logger.warning(f"nmap_scan: Invalid scan type {scan_type}, using default -sS")

    if ports and re.match(r'^[\d,-]+$', ports):
        cmd.extend(["-p", ports])
        logger.info(f"nmap_scan: Scanning ports: {ports}")
    elif ports:
        logger.warning(f"nmap_scan: Invalid port specification: {ports}")

    cmd.append(target)

    security_logger.info(f"Nmap scan initiated: target={target}, type={scan_type}, ports={ports or 'all'}")
    result = run_command_sync(cmd, timeout=120)
    logger.info(f"nmap_scan completed for target: {target}")

    return f"Nmap scan results for {target}:\n{result}"

@mcp.tool()
def netstat_connections(protocol: str = "all", state: str = ""):
    """Show network connections using netstat"""
    protocol = sanitize_input(protocol)
    state = sanitize_input(state)
    
    cmd = ["netstat", "-tulpn"]
    
    if protocol == "tcp":
        cmd = ["netstat", "-tlpn"]
    elif protocol == "udp":
        cmd = ["netstat", "-ulpn"]
    
    result = run_command_sync(cmd)
    
    # Filter by state if specified
    if state and protocol == "tcp":
        lines = result.split('\n')
        filtered_lines = [line for line in lines if state.upper() in line]
        result = '\n'.join(filtered_lines)
    
    return f"Network connections ({protocol}):\n{result}"

@mcp.tool()
def ss_connections(filter_expr: str = ""):
    """Show socket statistics using ss command"""
    filter_expr = sanitize_input(filter_expr)
    
    cmd = ["ss", "-tulpn"]
    if filter_expr:
        # Basic filter validation
        allowed_filters = ["state", "sport", "dport", "src", "dst"]
        if any(f in filter_expr for f in allowed_filters):
            cmd.append(filter_expr)
    
    result = run_command_sync(cmd)
    return f"Socket statistics:\n{result}"

@mcp.tool()
def ip_route_show(table: str = "main"):
    """Show routing table using ip route"""
    table = sanitize_input(table)
    
    if table not in ["main", "local", "all"]:
        table = "main"
    
    cmd = ["ip", "route", "show"]
    if table != "main":
        cmd.extend(["table", table])

    result = run_command_sync(cmd)
    return f"Routing table ({table}):\n{result}"

@mcp.tool()
def ip_addr_show(interface: str = ""):
    """Show network interface information using ip addr"""
    interface = sanitize_input(interface)
    
    cmd = ["ip", "addr", "show"]
    if interface:
        cmd.append(interface)
    
    result = run_command_sync(cmd)
    return f"IP address information{f' for {interface}' if interface else ''}:\n{result}"

@mcp.tool()
def traceroute_host(hostname: str = "", max_hops: str = "30"):
    """Perform traceroute to a host"""
    log_tool_usage("traceroute_host", {"hostname": hostname, "max_hops": max_hops})
    logger.info(f"traceroute_host called: hostname={hostname}, max_hops={max_hops}")

    hostname = sanitize_input(hostname)
    max_hops = sanitize_input(max_hops)

    if not hostname:
        return "Error: Hostname is required"

    if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        return "Error: Invalid hostname format"

    cmd = ["traceroute", "-m", max_hops, hostname]
    result = run_command_sync(cmd, timeout=120)

    return f"Traceroute to {hostname} (max hops: {max_hops}):\n{result}"

@mcp.tool()
def ping_host(hostname: str = "", count: str = "4"):
    """Ping a host"""
    log_tool_usage("ping_host", {"hostname": hostname, "count": count})
    logger.info(f"ping_host called: hostname={hostname}, count={count}")

    hostname = sanitize_input(hostname)
    count = sanitize_input(count)

    if not hostname:
        return "Error: Hostname is required"

    cmd = ["ping", "-c", count, hostname]
    result = run_command_sync(cmd)

    return f"Ping results for {hostname}:\n{result}"

@mcp.tool()
def dig_query(hostname: str = "", record_type: str = "A", dns_server: str = ""):
    """Perform a DNS lookup using dig"""
    log_tool_usage("dig_query", {"hostname": hostname, "record_type": record_type, "dns_server": dns_server})
    logger.info(f"dig_query called: hostname={hostname}, record_type={record_type}, dns_server={dns_server}")

    hostname = sanitize_input(hostname)
    record_type = sanitize_input(record_type).upper() or "A"
    dns_server = sanitize_input(dns_server)

    if not hostname:
        return "Error: Hostname is required"

    cmd = ["dig", "@" + dns_server if dns_server else "@[default]", hostname, record_type]
    if not dns_server:
        cmd = ["dig", hostname, record_type]
    result = run_command_sync(cmd)

    return f"dig {hostname} {record_type}:\n{result}"

@mcp.tool()
def nslookup_query(hostname: str = "", record_type: str = "A"):
    """Perform a DNS lookup using nslookup"""
    log_tool_usage("nslookup_query", {"hostname": hostname, "record_type": record_type})
    logger.info(f"nslookup_query called: hostname={hostname}, record_type={record_type}")

    hostname = sanitize_input(hostname)
    record_type = sanitize_input(record_type).upper() or "A"

    if not hostname:
        return "Error: Hostname is required"

    cmd = ["nslookup", "-type=" + record_type, hostname]
    result = run_command_sync(cmd)

    return f"nslookup {hostname} {record_type}:\n{result}"

@mcp.tool()
def process_network_usage():
    """List processes with active network connections and their bandwidth usage"""
    log_tool_usage("process_network_usage")
    logger.info("process_network_usage called")

    cmd = ["lsof", "-i", "-P", "-n"]
    result = run_command_sync(cmd, timeout=30)

    if "COMMAND" not in result:
        return "No processes with network connections found"

    # Parse output to get PID and command names
    processes = {}
    for line in result.split('\n')[1:]:
        parts = re.split(r'\s+', line.strip())
        if len(parts) >= 2:
            pid = parts[1]
            command = parts[0]
            processes[pid] = command

    if not processes:
        return "No processes with network connections found"

    # Get additional details for each process
    detailed_output = ["Processes with network connections:"]
    for pid, name in processes.items():
        cmd = ["ps", "-p", pid, "-o", "pid,ppid,user,%cpu,%mem,vsz,rss,stat,start,time,cmd"]
        ps_result = run_command_sync(cmd, timeout=10)
        detailed_output.append(f"\nProcess: {name} (PID: {pid})")
        detailed_output.append(ps_result)
    
    return "\n".join(detailed_output)

@mcp.tool()
def iptables_list():
    """List iptables firewall rules"""
    log_tool_usage("iptables_list")
    logger.info("iptables_list called")

    cmd = ["iptables", "-L", "-v", "-n"]
    result = run_command_sync(cmd, timeout=30)
    
    return f"IPTables firewall rules:\n{result}"

# Start the MCP server if this script is run directly
if __name__ == "__main__":
    # Configure MCP server from environment variables
    MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
    MCP_PORT = int(os.getenv("MCP_PORT", "8000"))
    MCP_TRANSPORT = os.getenv("MCP_TRANSPORT", "sse")

    logger.info("=" * 60)
    logger.info("Starting Network Debug MCP Server...")
    logger.info(f"Server version: {os.getenv('MCP_SERVER_VERSION', '1.0.0')}")
    logger.info(f"Server name: {os.getenv('MCP_SERVER_NAME', 'netdebug')}")
    logger.info(f"Log directory: {log_dir}")
    logger.info(f"Capture directory: {CAPTURE_DIR}")

    # Log binding info conditionally (older SDKs may not accept host/port for SSE)
    if MCP_TRANSPORT in ("http", "streamable-http", "sse"):
        logger.info(f"MCP Server will listen on {MCP_TRANSPORT} at {MCP_HOST}:{MCP_PORT}")
    else:
        logger.info(f"MCP Server will listen on {MCP_TRANSPORT}")
    logger.info("=" * 60)

    try:
        start_time = time.time()
        logger.info("Initializing MCP server...")
        try:
            # Preferred path: FastMCP.run supports host/port for http-like transports
            if MCP_TRANSPORT in ("http", "streamable-http", "sse"):
                mcp.run(transport=MCP_TRANSPORT, host=MCP_HOST, port=MCP_PORT)
            else:
                mcp.run(transport=MCP_TRANSPORT)
        except TypeError:
            # Fallback for SDKs where SSE doesn't accept host/port
            logger.warning("FastMCP.run signature doesn't accept host/port for this transport; applying fallback")
            if MCP_TRANSPORT == "sse" and hasattr(mcp, "start_server"):
                # Start server and ensure SSE-specific headers are applied
                server = mcp.start_server(host=MCP_HOST, port=MCP_PORT)
                if hasattr(server, "add_middleware"):
                    try:
                        from starlette.middleware.base import BaseHTTPMiddleware
                        from starlette.types import ASGIApp, Receive, Scope, Send

                        class SSEHeadersMiddleware(BaseHTTPMiddleware):
                            async def dispatch(self, request, call_next):
                                response = await call_next(request)
                                for header_key, header_value in DEFAULT_SSE_HEADERS.items():
                                    response.headers.setdefault(header_key, header_value)
                                return response

                        server.add_middleware(SSEHeadersMiddleware)
                        logger.info("SSE headers middleware applied successfully")
                    except Exception as middleware_exception:
                        logger.warning(f"Unable to apply SSE headers middleware: {middleware_exception}")
                else:
                    logger.warning("Server object does not support add_middleware; SSE headers must be ensured upstream")
            else:
                mcp.run(transport=MCP_TRANSPORT)
        # Should not reach here in normal operation
        uptime = time.time() - start_time
        logger.info(f"Server shutdown after {uptime:.2f} seconds")
    except KeyboardInterrupt:
        uptime = time.time() - start_time
        logger.info(f"Server stopped by user after {uptime:.2f} seconds")
        logger.info("Shutdown signal received, exiting gracefully")
    except Exception as e:
        uptime = time.time() - start_time
        logger.error(f"Server error after {uptime:.2f} seconds: {e}")
        logger.exception("Full exception details:")
        sys.exit(1)