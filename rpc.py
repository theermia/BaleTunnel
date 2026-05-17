import struct
import base64
import json
import ssl
import httpx
from urllib.parse import unquote
from settings import GRPC_HOST


def grpc_encode(payload: bytes) -> bytes:
    header = struct.pack(">BI", 0, len(payload))
    return header + payload


def grpc_decode(data: bytes) -> bytes:
    pos = 0
    result_data = None
    status = 0
    grpc_msg = ""

    while pos + 5 <= len(data):
        flag = data[pos]
        length = struct.unpack(">I", data[pos + 1:pos + 5])[0]
        pos += 5
        frame = data[pos:pos + length]
        pos += length

        if flag & 0x80:
            trailer = frame.decode("utf-8", errors="replace")
            import re
            sm = re.search(r"grpc-status:\s*(\d+)", trailer)
            if sm:
                status = int(sm.group(1))
            mm = re.search(r"grpc-message:\s*([^\r\n]+)", trailer)
            if mm:
                try:
                    grpc_msg = unquote(mm.group(1).strip())
                except Exception:
                    grpc_msg = mm.group(1).strip()
        else:
            result_data = frame

    if status != 0:
        raise GrpcError(status, grpc_msg or f"gRPC error {status}")

    return result_data or b""


class GrpcError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.grpc_status = status
        self.grpc_message = message


def grpc_call(service: str, method: str, payload: bytes, token: str = "") -> bytes:
    body = grpc_encode(payload)
    headers = {
        "Content-Type": "application/grpc-web+proto",
        "X-Grpc-Web": "1",
        "Origin": "https://web.bale.ai",
    }
    if token:
        headers["Cookie"] = f"access_token={token}"

    url = f"https://{GRPC_HOST}/{service}/{method}"
    resp = httpx.post(url, content=body, headers=headers, timeout=30.0, verify=False)
    return grpc_decode(resp.content)


def decode_jwt_payload(jwt: str) -> dict:
    if not jwt:
        return None
    parts = jwt.split(".")
    if len(parts) < 2:
        return None
    b64 = parts[1].replace("-", "+").replace("_", "/")
    padded = b64 + "=" * ((4 - len(b64) % 4) % 4)
    try:
        return json.loads(base64.b64decode(padded).decode("utf-8"))
    except Exception:
        return None


def fetch_access_token(jwt: str) -> str:
    headers = {"Authorization": f"Bearer {jwt}"}
    url = f"https://{GRPC_HOST}/set-cookie/"
    resp = httpx.get(url, headers=headers, timeout=30.0, follow_redirects=False, verify=False)
    cookies = resp.headers.get_list("set-cookie")
    for c in cookies:
        import re
        m = re.search(r"access_token=([^;]+)", c)
        if m:
            return m.group(1)
    return ""
