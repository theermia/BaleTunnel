# BaleTunnel Documentation

## Overview

BaleTunnel is a network tunneling tool designed to bypass severe internet restrictions. It leverages Bale Messenger infrastructure and WebRTC protocol to establish an encrypted tunnel between client and server. Network traffic appears as a regular voice call within Bale and is transported through LiveKit DataChannels.

## Architecture

```
[Client] --> SOCKS5 --> [LiveKit DataChannel] --> [Server] --> Internet
```

- Client creates a local SOCKS5 proxy
- Traffic is sent to the server via WebRTC DataChannel
- Server forwards traffic to the final destination
- All communications are encrypted

---

## Installation

### Requirements

- Python 3.10 or higher
- Internet access (at minimum, access to Bale servers)
- Active Bale Messenger account

### Setup

```bash
cd BaleTunnel
pip install -r requirements.txt
```

---

## Server Mode

The server must run on a machine with unrestricted internet access.

```bash
python src/app.py server
```

### Authentication

```
> login
Phone number (e.g. +98912...): +989121234567
Code sent. Registered: True
Enter verification code: 12345
Login successful.
```

### Managing Requests

When a client requests connection, it enters the pending queue:

```
> pending
Pending calls (1):
  Call 5913263170600257563 from caller 912116268
```

Accept a request:
```
> accept 5913263170600257563
```

Accept and save to allow-list (future connections auto-accepted):
```
> accept 5913263170600257563 --save
```

Reject and block:
```
> reject 5913263170600257563 --block
```

### Access Control

```
> admission              Show allow-list
> allow 912116268        Manually add to allow-list
> block 912116268        Block user
> unblock 912116268      Unblock user
> blacklist              Show block-list
```

### Client Management

```
> clients
Connected clients (1):
  [5913263170600257563] caller 912116268 rx=1024B tx=2048B

> kick 5913263170600257563
Kick: ok
```

### Disconnect All

```
> disconnect
Disconnected.
```

---

## Client Mode

The client runs on the user's device and creates a local SOCKS5 proxy.

```bash
python src/app.py client --port 1080
```

### Connection Steps

1. Authenticate:
```
> login
Phone number (e.g. +98912...): +989129876543
Login successful.
```

2. List contacts:
```
> peers
Contacts (2):
  [1613707444] ermia (@ermiah72)
  [912116268] user2
```

3. Connect to server:
```
> connect 1613707444
Connecting to peer 1613707444...
[Tunnel/C] WebRTC tunnel ready
```

### Proxy Configuration

After "WebRTC tunnel ready" appears, the SOCKS5 proxy is active.

Command line:
```bash
curl --socks5-hostname 127.0.0.1:1080 http://ifconfig.me
```

Firefox:
- Settings > Network Settings > Manual proxy configuration
- SOCKS Host: 127.0.0.1
- Port: 1080
- SOCKS v5
- Enable "Proxy DNS when using SOCKS v5"

System-wide:
- Configure SOCKS5 proxy at 127.0.0.1:1080

---

## CLI Reference

| Command | Mode | Description |
|---------|------|-------------|
| `login` | Both | Authenticate with phone number |
| `logout` | Both | Sign out and clear credentials |
| `status` | Both | Display connection status |
| `peers` | Both | List contacts |
| `connect <id>` | Client | Connect to server peer |
| `disconnect` | Both | Disconnect tunnel or all clients |
| `pending` | Server | Show pending requests |
| `accept <id> [--save]` | Server | Accept pending request |
| `reject <id> [--block]` | Server | Reject pending request |
| `clients` | Server | Show connected clients |
| `kick <key>` | Server | Disconnect a specific client |
| `allow <uid>` | Server | Add user to allow-list |
| `block <uid>` | Server | Block a user |
| `unblock <uid>` | Server | Unblock a user |
| `admission` | Server | Display allow-list |
| `blacklist` | Server | Display block-list |
| `exit` / `quit` | Both | Exit the program |

---

## Troubleshooting

| Error | Cause and Solution |
|-------|-------------------|
| InvalidPeer | Incorrect server ID. Use `peers` to find the correct one |
| Timeout | Unstable connection or server is offline |
| Session expired | Session has expired. Run `logout` then `login` again |
| SSL error | Ensure `ca_bundle.pem` is present in the src directory |
| WS Reconnecting | Normal behavior. WebSocket reconnects automatically |

---

## Security Notes

- The configuration file contains authentication tokens. Do not share it.
- The proxy listens on all interfaces (0.0.0.0) by default. Configure firewall rules if needed.
- DNS must be routed through the proxy (use socks5-hostname, not socks5).

---

## Technical Details

- WebRTC connection operates independently of WebSocket. Tunnel remains active during temporary WS disconnections.
- Internal SNAT system supports up to 253 simultaneous client connections.
- Egress filter prevents access to private, loopback, and link-local addresses.
- Per-client bandwidth throttling via token bucket algorithm.

---

## Developer

Developed by **Ermia**

Documentation written with Claude Sonnet 4.6.

Telegram: [@theermia](https://t.me/theermia)
Channel: [@thisisermia](https://t.me/thisisermia)

---

## License

MIT License
