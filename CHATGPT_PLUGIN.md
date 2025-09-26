# Network Debug MCP - ChatGPT Plugin Deployment Guide

This guide explains how to deploy your Network Debug MCP server as a ChatGPT plugin.

## Prerequisites

1. A publicly accessible server with Docker installed
2. A domain name pointing to your server
3. SSL certificate for your domain (required for ChatGPT plugins)

## Deployment Steps

### 1. Prepare Your Server

Set up a server with Docker and Docker Compose installed. Make sure ports 80 and 443 are open for HTTP/HTTPS traffic.

### 2. Configure SSL with Nginx

Create a `docker-compose.override.yml` file to add Nginx as a reverse proxy:

```yaml
services:
  network-debug-mcp:
    # Remove the ports section from the original docker-compose.yml
    ports: []
    networks:
      - app-network

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/conf.d:/etc/nginx/conf.d
      - ./nginx/ssl:/etc/nginx/ssl
      - ./logo.png:/usr/share/nginx/html/config/logo.png
      - ./chatgpt/config/openapi.yaml:/usr/share/nginx/html/config/openapi.yaml
      - ./.well-known:/usr/share/nginx/html/.well-known
    depends_on:
      - network-debug-mcp
    networks:
      - app-network

networks:
  app-network:
    driver: bridge
```

### 3. Create Nginx Configuration

Create the Nginx configuration file at `nginx/conf.d/default.conf`:

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name your-domain.com;
    
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    
    # Serve static files under /config
    location /config/ {
        root /usr/share/nginx/html;
        try_files $uri =404;
    }
    
    location /.well-known/ {
        root /usr/share/nginx/html;
    }
    
    # Proxy API requests to the MCP server
    location / {
        proxy_pass http://network-debug-mcp:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 4. Update Plugin Configuration Files

1. Update the URLs in `.well-known/ai-plugin.json`:

```json
{
  "api": {
    "url": "https://your-domain.com/config/openapi.yaml"
  },
  "logo_url": "https://your-domain.com/config/logo.png",
  "legal_info_url": "https://your-domain.com/config/legal"
}
```

2. Update the server URL in `openapi.yaml`:

```yaml
servers:
  - url: https://your-domain.com
```

### 5. Create a Logo

Replace the placeholder `logo.png` file with a real PNG image (112x112 pixels recommended).

### 6. Deploy Your Plugin

1. Copy all files to your server
2. Place your SSL certificates in the `nginx/ssl` directory as `cert.pem` and `key.pem`
3. Start the containers:

```bash
docker compose up -d
```

### 7. Register with ChatGPT

1. Go to [https://chat.openai.com/plugins](https://chat.openai.com/plugins)
2. Click "Develop your own plugin"
3. Enter your domain name (e.g., `your-domain.com`)
4. Follow the prompts to complete the registration

## Testing Your Plugin

After registration, you can test your plugin in ChatGPT by:

1. Starting a new conversation
2. Selecting your plugin from the plugin picker
3. Asking ChatGPT to perform network diagnostics using your plugin

Example prompts:
- "Scan port 80 on example.com"
- "Ping google.com"
- "Trace the route to 8.8.8.8"
- "Show my network interfaces"

## Security Considerations

This plugin provides access to powerful network tools. Consider these security measures:

1. Limit the commands and parameters available through the API
2. Implement rate limiting to prevent abuse
3. Monitor logs for suspicious activity
4. Consider requiring authentication for production use

## Troubleshooting

If you encounter issues:

1. Check the container logs: `docker-compose logs`
2. Verify your SSL certificates are valid
3. Ensure your domain is correctly pointing to your server
4. Test the API directly using curl or a browser