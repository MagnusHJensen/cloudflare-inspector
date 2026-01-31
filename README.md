# Cloudflare Inspector

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

A simple tool that watches HTTP traffic on a specific port. It shows you what requests and responses are going through, including headers and body content.

I made this tool to help debug Cloudflare Tunnels by inspecting the HTTP traffic going through them.

## Usage

```bash
# Monitor default port 8080
sudo ./cloudflare-inspector

# Monitor a different port
sudo ./cloudflare-inspector -port 9000

# See help
./cloudflare-inspector -h
```

## Example Request/Response

```
┌─ HTTP REQUEST [2026-01-31 14:23:17]
├─ Method: POST
├─ URL: /api/v1/users/profile
├─ Host: app.example.com
├─ User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36
├─ Content-Type: application/json
├─ Content-Length: 145
├─ Body Size: 145 bytes
├─ Connection: 192.168.1.45 → 192.168.1.1
├─ Cdn-Loop: [cloudflare; loops=1]
├─ Cf-Visitor: [{"scheme":"https"}]
├─ Cf-Warp-Tag-Id: [a1b2c3d4-e5f6-7890-abcd-ef1234567890]
├─ X-Forwarded-For: [203.0.113.42]
├─ X-Forwarded-Proto: [https]
├─ Accept-Encoding: [gzip, br, deflate]
├─ Cf-Connecting-Ip: [203.0.113.42]
├─ Cf-Ipcountry: [US]
├─ Cf-Ray: [8a5b9c2d1e4f6789-LAX]
├─ Authorization: [Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...]
├─ Accept: [application/json, text/plain, */*]
├─ Body preview:
├  {"firstName":"John","lastName":"Doe","email":"john.doe@company.com","preferences":{"theme":"dark","notifications":true}}
└─ Protocol: HTTP/1.1

┌─ HTTP RESPONSE [2026-01-31 14:23:17]
├─ Status: 200 OK
├─ Content-Type: application/json; charset=utf-8
├─ Content-Length: 312
├─ Body Size: 312 bytes
├─ Connection: 192.168.1.1 ← 192.168.1.45
├─ X-Content-Type-Options: [nosniff]
├─ Cache-Control: [no-cache, private]
├─ Date: [Fri, 31 Jan 2026 19:23:17 GMT]
├─ Set-Cookie: [session_id=abc123def456; HttpOnly; Secure; SameSite=Strict]
├─ Body preview:
├  {"success":true,"data":{"userId":12345,"firstName":"John","lastName":"Doe","email":"john.doe@company.com","created":"2024-03-15T10:30:00Z","lastLogin":"2026-01-31T14:23:17Z"},"message":"Profile updated successfully"}
└─ Protocol: HTTP/1.1
```

## Options

| Flag  | Default | Description                  |
| ----- | ------- | ---------------------------- |
| -port | 8080    | Port to monitor HTTP traffic |
| -h    |         | Show help                    |

## Why SUDO?

You need `sudo` because the tool captures network packets directly from your system. This requires admin privileges to access the network interface.

## Platform Support

This tool currently works on **macOS only**. I might add support for Linux and Windows later.

## Future Plans

Right now this is just a packet sniffer that dumps HTTP traffic to your terminal. The plan is to build this into a GUI tool (like ngrok has) for better packet inspection and analysis.

## Contributions

Contributions are welcome, as you can see it's a pretty simple tool put together from a few examples.
