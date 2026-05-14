# BaleTunnel

BaleTunnel is a network tunneling tool that leverages the infrastructure of [Bale Messenger](https://bale.ai) combined with the WebRTC protocol to bypass heavy internet restrictions. Network traffic is transmitted through LiveKit's encrypted DataChannel and appears as a regular voice call within the Bale platform.

---

## Features

- Network traffic tunneling via WebRTC DataChannel
- End-to-end encryption powered by LiveKit
- SOCKS5 proxy for routing application traffic
- Server and client operating modes
- Access control system (allow-list / block-list)
- Configurable per-client bandwidth limits
- Interactive command-line interface (CLI)
- Cross-platform: Windows, Linux, and macOS
- No GUI required

---

## Prerequisites

- Python 3.10 or higher
- An active Bale Messenger account

---

## Installation

```bash
cd BaleTunnel
pip install -r requirements.txt
```

---

## Quick Start

### Server (on a machine with unrestricted internet)

```bash
python src/app.py server
```

Then enter the `login` command and authenticate with your phone number.

### Client (on the restricted device)

```bash
python src/app.py client --port 1080
```

After logging in, use `peers` to list contacts and `connect <server_id>` to establish a tunnel to the server.

---

## CLI Commands

| Command | Mode | Description |
|---------|------|-------------|
| `login` | Both | Log in with phone number |
| `logout` | Both | Log out |
| `status` | Both | Show connection status |
| `peers` | Both | List contacts |
| `connect <id>` | Client | Connect to a server |
| `disconnect` | Both | Disconnect |
| `pending` | Server | Show pending requests |
| `accept <id> [--save]` | Server | Accept a request |
| `reject <id> [--block]` | Server | Reject a request |
| `clients` | Server | Show connected clients |
| `kick <key>` | Server | Disconnect a client |
| `allow <uid>` | Server | Add to allow-list |
| `block <uid>` | Server | Block a user |
| `unblock <uid>` | Server | Unblock a user |
| `admission` | Server | Show allow-list |
| `blacklist` | Server | Show block-list |
| `exit` | Both | Exit the application |

---

## Using the Proxy

Once the tunnel is established, a SOCKS5 proxy becomes available on the specified port:

```bash
curl --socks5-hostname 127.0.0.1:1080 http://ifconfig.me
```

Configure your browser or OS proxy settings to use SOCKS5 at `127.0.0.1:1080`. Enabling **"Proxy DNS"** (remote DNS resolution) is required.

---

## Benchmarks

The following results were obtained during real-world testing:

| Parameter | Details |
|-----------|---------|
| **Server location** | Infomaniak, Switzerland |
| **Client connection** | Iranian ADSL (Mokhaberat / TCI) |
| **Download speed** | 8–10 Mbps |
| **Upload speed** | Not measured |
| **Latency** | 600–1000 ms |

> **Note:** Performance depends on network conditions, server load, and ISP throttling. Results may vary.

---

## Project Structure

```
BaleTunnel/
├── src/
│   ├── app.py           # Entry point and CLI
│   ├── ws_client.py     # WebSocket connection manager
│   ├── relay.py         # Tunnel engine and SOCKS5 proxy
│   ├── transport.py     # LiveKit transport layer
│   ├── protocol.py      # Protobuf codecs
│   ├── rpc.py           # gRPC-web calls
│   ├── persistence.py   # Configuration storage
│   ├── settings.py      # Constants and configuration
│   └── ca_bundle.pem    # SSL certificate bundle
├── docs/
│   ├── guide-fa.md      # Persian documentation
│   └── guide-en.md      # English documentation
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Technical Notes

- The WebRTC connection operates independently of the WebSocket signaling channel. If the WebSocket drops temporarily, the active tunnel remains intact.
- Configuration is automatically persisted in the application's working directory.
- The internal SNAT system supports up to 253 concurrent client connections.
- An egress filter prevents access to private and loopback addresses from the tunnel.

---

## Author

Developed by **Ermia**

Documentation for this project was written with the assistance of Claude Sonnet 4.6.

For questions and suggestions:
- Telegram: [@theermia](https://t.me/theermia)
- Channel: [@thisisermia](https://t.me/thisisermia)

---

## Background

This project was developed in response to the severe internet restrictions imposed in Iran. It only functions when voice calls through Bale Messenger can be established via an overseas server.

*Hoping for better days for Iran.*

---

## License

MIT License
