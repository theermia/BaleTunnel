import os
import sys
import json
from pathlib import Path

RUNTIME_DIR = Path(os.path.dirname(os.path.abspath(sys.argv[0])))

WS_URL = "wss://next-ws.bale.ai/ws/"
GRPC_HOST = "next-ws.bale.ai"
API_VERSION = 151668
PROTO_VERSION = 1

AUTH_APP_ID = 4
AUTH_API_KEY = "C28D46DC4C3A7A26564BFCC48B929086A95C93C98E789A19847BEE8627DE4E7D"
SENDCODE_SMS = 3

PEERTYPE_PRIVATE = 1
PEERTYPE_GROUP = 2
EXPEERTYPE_PRIVATE = 1
EXPEERTYPE_GROUP = 2

TUNNEL_PREFIX = "T:"
CHUNK_SIZE = 3000
LK_CHUNK = 65000

CALL_ACCEPTED_TIMEOUT_S = 90
PEER_TIMEOUT_S = 5
PEER_JOIN_TIMEOUT_S = 5
PENDING_TIMEOUT_S = 60
PENDING_SWEEP_S = 15

DEFAULT_LIMIT_KBPS = 50000
MAX_LIMIT_KBPS = 100000
THROTTLE_FLAG_S = 2

MAX_CLIENTS_DEFAULT = 5
MAX_CLIENTS_LIMIT = 253


def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description="BaleTunnel - Secure relay over Bale Messenger")
    parser.add_argument("mode", nargs="?", choices=["client", "server"], default="client",
                        help="Operating mode (default: client)")
    parser.add_argument("--port", type=int, default=1080,
                        help="SOCKS5 listen port for client mode (default: 1080)")
    parser.add_argument("--peer-id", type=int, default=0,
                        help="Server peer ID for client mode")
    parser.add_argument("--peer-type", type=int, default=PEERTYPE_PRIVATE,
                        help="Server peer type (1=private, 2=group)")
    return parser.parse_args()
