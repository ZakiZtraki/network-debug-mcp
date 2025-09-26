import os
import sys
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
import importlib.util

# Import the MCP server module
spec = importlib.util.spec_from_file_location("netdebug_server", os.path.join(os.path.dirname(__file__), "netdebug_server.py"))
netdebug_server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(netdebug_server)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("netdebug-api")

# Create FastAPI app
app = FastAPI(
    title=os.getenv("API_TITLE", "Network Debug MCP"),
    description=os.getenv("API_DESCRIPTION", "A Model Context Protocol (MCP) server providing network debugging and analysis tools through a Kali Linux container."),
    version=os.getenv("API_VERSION", "1.0.0")
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define request models
class NmapScanRequest(BaseModel):
    target: str = Field(..., description="Target IP or hostname")
    scan_type: str = Field("-sS", description="Scan type (-sS, -sT, -sU, -sA, -sF, -sN, -sX, -sn)")
    ports: str = Field("", description="Port range (e.g., 22,80,443 or 1-1000)")

class TcpdumpCaptureRequest(BaseModel):
    interface: str = Field("eth0", description="Network interface to capture on")
    count: str = Field("10", description="Number of packets to capture")
    filter_expr: str = Field("", description="Filter expression for tcpdump")

class PingHostRequest(BaseModel):
    hostname: str = Field(..., description="Hostname or IP to ping")
    count: str = Field("4", description="Number of ping packets to send")

class TracerouteHostRequest(BaseModel):
    hostname: str = Field(..., description="Hostname or IP to trace")
    max_hops: str = Field("30", description="Maximum number of hops")

class IpAddrShowRequest(BaseModel):
    interface: str = Field("", description="Specific interface to show (optional)")

class IpRouteShowRequest(BaseModel):
    table: str = Field("main", description="Routing table to show (main, local, all)")

class NslookupQueryRequest(BaseModel):
    hostname: str = Field(..., description="Hostname to lookup")
    record_type: str = Field("A", description="DNS record type (A, AAAA, MX, NS, TXT, PTR, CNAME)")

class DigQueryRequest(BaseModel):
    hostname: str = Field(..., description="Hostname to lookup")
    record_type: str = Field("A", description="DNS record type (A, AAAA, MX, NS, TXT, PTR, CNAME, SOA)")
    dns_server: str = Field("", description="DNS server to use (optional)")

class ApiResponse(BaseModel):
    result: str

# Define API endpoints
@app.post("/nmap_scan", response_model=ApiResponse)
async def api_nmap_scan(request: NmapScanRequest):
    try:
        result = netdebug_server.nmap_scan(
            target=request.target,
            scan_type=request.scan_type,
            ports=request.ports
        )
        return {"result": result}
    except Exception as e:
        logger.error(f"Error in nmap_scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tcpdump_capture", response_model=ApiResponse)
async def api_tcpdump_capture(request: TcpdumpCaptureRequest):
    try:
        result = netdebug_server.tcpdump_capture(
            interface=request.interface,
            count=request.count,
            filter_expr=request.filter_expr
        )
        return {"result": result}
    except Exception as e:
        logger.error(f"Error in tcpdump_capture: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/ping_host", response_model=ApiResponse)
async def api_ping_host(request: PingHostRequest):
    try:
        result = netdebug_server.ping_host(
            hostname=request.hostname,
            count=request.count
        )
        return {"result": result}
    except Exception as e:
        logger.error(f"Error in ping_host: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/traceroute_host", response_model=ApiResponse)
async def api_traceroute_host(request: TracerouteHostRequest):
    try:
        result = netdebug_server.traceroute_host(
            hostname=request.hostname,
            max_hops=request.max_hops
        )
        return {"result": result}
    except Exception as e:
        logger.error(f"Error in traceroute_host: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/ip_addr_show", response_model=ApiResponse)
async def api_ip_addr_show(request: IpAddrShowRequest):
    try:
        result = netdebug_server.ip_addr_show(
            interface=request.interface
        )
        return {"result": result}
    except Exception as e:
        logger.error(f"Error in ip_addr_show: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/ip_route_show", response_model=ApiResponse)
async def api_ip_route_show(request: IpRouteShowRequest):
    try:
        result = netdebug_server.ip_route_show(
            table=request.table
        )
        return {"result": result}
    except Exception as e:
        logger.error(f"Error in ip_route_show: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/nslookup_query", response_model=ApiResponse)
async def api_nslookup_query(request: NslookupQueryRequest):
    try:
        result = netdebug_server.nslookup_query(
            hostname=request.hostname,
            record_type=request.record_type
        )
        return {"result": result}
    except Exception as e:
        logger.error(f"Error in nslookup_query: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/dig_query", response_model=ApiResponse)
async def api_dig_query(request: DigQueryRequest):
    try:
        result = netdebug_server.dig_query(
            hostname=request.hostname,
            record_type=request.record_type,
            dns_server=request.dns_server
        )
        return {"result": result}
    except Exception as e:
        logger.error(f"Error in dig_query: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": os.getenv("API_VERSION", "1.0.0")}

# Root endpoint with API information
@app.get("/")
async def root():
    return {
        "name": os.getenv("API_TITLE", "Network Debug MCP API"),
        "description": os.getenv("API_DESCRIPTION", "API for network debugging and analysis tools"),
        "version": os.getenv("API_VERSION", "1.0.0"),
        "endpoints": [
            "/nmap_scan",
            "/tcpdump_capture",
            "/ping_host",
            "/traceroute_host",
            "/ip_addr_show",
            "/ip_route_show",
            "/nslookup_query",
            "/dig_query"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("API_PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)