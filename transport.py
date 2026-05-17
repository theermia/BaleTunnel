import asyncio
import struct
from typing import Optional, Callable

try:
    from livekit import rtc as livekit_rtc
    HAS_LIVEKIT = True
except ImportError:
    HAS_LIVEKIT = False

NORMAL_QUEUE_HIGH = 64
NORMAL_QUEUE_LOW = 16


class LiveKitTransport:
    def __init__(self):
        self.room: Optional[object] = None
        self.on_data: Optional[Callable] = None
        self.on_disconnected: Optional[Callable] = None
        self.on_drain: Optional[Callable] = None
        self.has_peer: bool = False
        self._urgent_queue: list = []
        self._normal_queue: list = []
        self._drain_pending: bool = False
        self._rx_pkts = 0
        self._rx_bytes = 0
        self._tx_pkts = 0
        self._tx_bytes = 0
        self._caller_id = 0
        self._caller_name = None
        self._call_key = None
        self._connected_at = 0
        self._up_bucket = None
        self._down_bucket = None

    @property
    def pressured(self) -> bool:
        return len(self._normal_queue) >= NORMAL_QUEUE_HIGH

    async def connect(self, url: str, token: str):
        if not HAS_LIVEKIT:
            raise RuntimeError("livekit SDK not installed. Install with: pip install livekit")

        room = livekit_rtc.Room()

        @room.on("data_received")
        def on_data_received(packet, *args, **kwargs):
            raw = packet.data if hasattr(packet, 'data') else packet
            if self.on_data:
                self.on_data(raw)

        @room.on("disconnected")
        def on_disconnected(*args, **kwargs):
            self._teardown()

        @room.on("participant_connected")
        def on_participant_connected(*args, **kwargs):
            self.has_peer = True

        @room.on("participant_disconnected")
        def on_participant_disconnected(*args, **kwargs):
            if room.remote_participants is not None and len(room.remote_participants) == 0:
                self._teardown()

        await room.connect(url, token, options=livekit_rtc.RoomOptions(auto_subscribe=False))
        self.room = room
        if room.remote_participants and len(room.remote_participants) > 0:
            self.has_peer = True
        print("[LiveKit] Connected")

    def _teardown(self):
        if not self.room:
            return
        room = self.room
        self.room = None
        self.has_peer = False
        self._urgent_queue = []
        self._normal_queue = []
        try:
            asyncio.get_event_loop().create_task(room.disconnect())
        except Exception:
            pass
        if self.on_disconnected:
            self.on_disconnected()

    async def send(self, data: bytes):
        if not self.room:
            return
        # Flow control: yield if queue is too full to prevent memory explosion
        while len(self._normal_queue) >= NORMAL_QUEUE_HIGH:
            await asyncio.sleep(0)
            if not self.room:
                return
        self._normal_queue.append(data)
        await self._drain()

    async def send_urgent(self, data: bytes):
        if not self.room:
            return
        self._urgent_queue.append(data)
        await self._drain()

    async def send_lossy(self, data: bytes):
        if not self.room:
            return
        try:
            await self.room.local_participant.publish_data(data, reliable=False)
        except Exception as e:
            print(f"[LK] LOSSY send failed: {e}")

    async def _drain(self):
        if not self.room:
            return
        sent = 0
        while self._urgent_queue or self._normal_queue:
            data = (self._urgent_queue.pop(0) if self._urgent_queue
                    else self._normal_queue.pop(0))
            try:
                await self.room.local_participant.publish_data(data, reliable=True)
            except Exception as e:
                print(f"[LK] send failed: {e}")
                break
            sent += 1
            # Yield every 8 packets to prevent event loop starvation
            if sent % 8 == 0:
                await asyncio.sleep(0)
        if self._drain_pending:
            self._drain_pending = False
            if self.on_drain:
                self.on_drain()
                self.on_drain = None

    def disconnect(self):
        self._teardown()


def lk_encode(obj: dict) -> bytes:
    t = obj["t"]

    if t == "I":
        data = obj["data"]
        out = bytearray(len(data) + 1)
        out[0] = 0x49  # 'I'
        out[1:] = data
        return bytes(out)

    sid_bytes = bytes.fromhex(obj["s"])
    hdr = bytes([ord(t)])

    if t == "C":
        host = obj["h"].encode("utf-8")
        meta = struct.pack(">HB", obj["p"], len(host))
        return hdr + sid_bytes + meta + host

    if t == "A":
        return hdr + sid_bytes + bytes([1 if obj.get("ok") else 0])

    if t == "D":
        return hdr + sid_bytes + obj["data"]

    if t == "U":
        host = obj["h"].encode("utf-8")
        meta = struct.pack(">HB", obj["p"], len(host))
        return hdr + sid_bytes + meta + host + obj["data"]

    return hdr + sid_bytes


def lk_decode(buf: bytes) -> Optional[dict]:
    if len(buf) < 1:
        return None

    t = chr(buf[0])

    if t == "I":
        return {"t": "I", "data": buf[1:]}

    if len(buf) < 7:
        return None

    s = buf[1:7].hex()
    r = buf[7:]

    if t == "C":
        if len(r) < 3:
            return None
        port = struct.unpack(">H", r[0:2])[0]
        host_len = r[2]
        host = r[3:3 + host_len].decode("utf-8")
        return {"t": "C", "s": s, "h": host, "p": port}

    if t == "A":
        ok = len(r) > 0 and r[0] != 0
        return {"t": "A", "s": s, "ok": ok}

    if t == "D":
        return {"t": "D", "s": s, "data": r}

    if t == "X":
        return {"t": "X", "s": s}

    if t == "U":
        if len(r) < 3:
            return None
        port = struct.unpack(">H", r[0:2])[0]
        host_len = r[2]
        host = r[3:3 + host_len].decode("utf-8")
        data = r[3 + host_len:]
        return {"t": "U", "s": s, "h": host, "p": port, "data": data}

    return None
