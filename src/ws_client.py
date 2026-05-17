import asyncio
import ssl
import time
import json
from typing import Optional, Callable, List

import websockets
from websockets.exceptions import ConnectionClosed, ConnectionClosedError

from settings import (
    WS_URL, API_VERSION, PROTO_VERSION,
    PEERTYPE_PRIVATE, PEERTYPE_GROUP, EXPEERTYPE_PRIVATE, EXPEERTYPE_GROUP,
)
from persistence import cfg_get, cfg_set, cfg_delete
from protocol import (
    encode_handshake, encode_ping, encode_rpc_request,
    decode_server_frame, decode_subscribe_response, decode_call_response,
    decode_rpc_error, decode_get_contacts_response, decode_load_users_response,
    decode_user_entity, build_accept_call_request, build_discard_call_request,
    build_start_call_request, build_get_contacts_request,
    build_load_users_request, build_send_message_request,
)
from rpc import decode_jwt_payload


def _load_persisted_token() -> str:
    return cfg_get("token", "")


def _persist_token(t: str):
    if t:
        cfg_set("token", t)
    else:
        cfg_delete("token")


class BaleWsClient:
    def __init__(self):
        self.ws = None
        self.rpc_index = 0
        self.ping_counter = 0
        self.ready = False
        self.connecting = False
        self.auto_reconnect = False
        self.session_expired = False
        self.version_mismatch = False
        self._last_inbound_ts = 0
        self._reconnect_attempt = 0
        self._access_token = _load_persisted_token()
        self.self_info = None  # {id, name, nick}
        self._user_name_cache = {}
        self.peers = []
        self.messages = []
        self.subscribe_idx = None

        self._pending = {}

        self._on_call_received: List[Callable] = []
        self._on_call_ended: List[Callable] = []
        self._on_call_accepted: List[Callable] = []

        self.tunnel = None

        self._ping_task = None
        self._online_task = None
        self._recv_task = None
        self._reconnect_task = None

    @property
    def access_token(self) -> str:
        return self._access_token

    @access_token.setter
    def access_token(self, value: str):
        self._access_token = value or ""
        _persist_token(self._access_token)

    def add_on_call_received(self, cb: Callable):
        self._on_call_received.append(cb)
        return lambda: self._on_call_received.remove(cb) if cb in self._on_call_received else None

    def add_on_call_ended(self, cb: Callable):
        self._on_call_ended.append(cb)
        return lambda: self._on_call_ended.remove(cb) if cb in self._on_call_ended else None

    def add_on_call_accepted(self, cb: Callable):
        self._on_call_accepted.append(cb)
        return lambda: self._on_call_accepted.remove(cb) if cb in self._on_call_accepted else None

    async def connect(self):
        if not self.access_token:
            raise RuntimeError("No access token set")

        if self.ws:
            old = self.ws
            self.ws = None
            try:
                await old.close()
            except Exception:
                pass
            self._cancel_tasks()
            self._drain_pending("superseded by new connect()")

        self.session_expired = False
        self.version_mismatch = False
        self.auto_reconnect = True
        self.connecting = True
        print(f"[WS] Connecting to {WS_URL}")

        try:
            extra_headers = {
                "Cookie": f"access_token={self.access_token}",
                "Origin": "https://web.bale.ai",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            }
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            self.ws = await websockets.connect(
                WS_URL,
                additional_headers=extra_headers,
                max_size=2**20,
                ping_interval=30,
                ping_timeout=20,
                close_timeout=10,
                ssl=ssl_ctx,
            )
            self.connecting = False
            print("[WS] Open - sending handshake")
            await self.ws.send(encode_handshake())
            self._recv_task = asyncio.create_task(self._recv_loop())
        except Exception as e:
            self.connecting = False
            print(f"[WS] Connection failed: {e}")
            if self.auto_reconnect:
                await self._schedule_reconnect()

    def _cancel_tasks(self):
        for task in [self._ping_task, self._online_task, self._recv_task, self._reconnect_task]:
            if task and not task.done():
                task.cancel()
        self._ping_task = None
        self._online_task = None
        self._recv_task = None
        self._reconnect_task = None

    async def disconnect(self):
        self.auto_reconnect = False
        self.ready = False
        self.connecting = False
        self._cancel_tasks()
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass
            self.ws = None
        self._drain_pending("WS disconnected by user")
        print("[WS] Disconnected by user")

    def _drain_pending(self, reason: str):
        if not self._pending:
            return
        for idx, entry in list(self._pending.items()):
            fut = entry["future"]
            if not fut.done():
                fut.set_exception(RuntimeError(reason))
        self._pending.clear()

    async def _recv_loop(self):
        try:
            async for message in self.ws:
                self._last_inbound_ts = time.time()
                try:
                    data = message if isinstance(message, bytes) else message.encode('latin-1')
                    frame = decode_server_frame(data)
                    if not frame.get("pong") and not frame.get("response"):
                        print(f"[WS] frame keys: {list(frame.keys())}")
                    await self._on_frame(frame)
                except Exception as e:
                    print(f"[WS] Decode error: {e} (first 20 bytes: {data[:20].hex() if isinstance(data, bytes) else 'N/A'})")
        except (ConnectionClosed, ConnectionClosedError) as e:
            code = getattr(e, 'code', 1006) or 1006
            print(f"[WS] ConnectionClosed code={code}")
            await self._handle_close(code)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"[WS] recv error: {type(e).__name__}: {e}")
            await self._handle_close(1006)

    async def _handle_close(self, code: int):
        self._cancel_tasks()
        self.ready = False
        self.connecting = False
        self._drain_pending(f"WS closed (code {code})")

        if code == 4401:
            print("[WS] 4401 Unauthenticated - token expired")
            self.auto_reconnect = False
            self.access_token = ""
            self.session_expired = True
        elif self.auto_reconnect:
            await self._schedule_reconnect()
        else:
            print(f"[WS] Closed {code}")

    async def _schedule_reconnect(self):
        attempt = self._reconnect_attempt
        self._reconnect_attempt += 1
        delay = min(1 * (2 ** min(attempt, 4)), 15)
        print(f"[WS] Reconnecting in {delay}s (attempt {attempt + 1})")
        self._reconnect_task = asyncio.create_task(self._reconnect_after(delay))

    async def _reconnect_after(self, delay: float):
        await asyncio.sleep(delay)
        if self.auto_reconnect:
            await self.connect()

    async def _on_frame(self, frame: dict):
        if "handshakeResponse" in frame:
            hs = frame["handshakeResponse"]
            print(f"[WS] Handshake: proto={hs.get('mkprotoVersion')} api={hs.get('apiVersion')}")
            if hs.get("mkprotoVersion") == PROTO_VERSION and hs.get("apiVersion") == API_VERSION:
                self.ready = True
                self._reconnect_attempt = 0
                print("[WS] Ready - subscribing to updates")
                await self._subscribe()
                self._start_ping()
                self._start_set_online_loop()
                if self.tunnel:
                    await self.tunnel.on_ws_ready()
                asyncio.create_task(self._load_self_safe())
                asyncio.create_task(self._load_contacts_safe())
            else:
                print(f"[WS] Version mismatch: server proto={hs.get('mkprotoVersion')} api={hs.get('apiVersion')}")
                self.version_mismatch = True
                self.auto_reconnect = False
                if self.ws:
                    await self.ws.close()

        if "response" in frame:
            rpc = frame["response"]
            idx = rpc.get("index")
            if idx in self._pending:
                entry = self._pending.pop(idx)
                fut = entry["future"]
                if fut.done():
                    pass
                elif "error" in rpc and rpc["error"]:
                    err_info = decode_rpc_error(rpc["error"])
                    print(f"[WS] RPC <- {entry['service']}/{entry['method']} idx={idx} ERR (code={err_info['code']})")
                    fut.set_exception(
                        RuntimeError(f"{err_info['message']} (RPC code {err_info['code']})")
                    )
                else:
                    fut.set_result(rpc.get("response", b""))
            elif idx == self.subscribe_idx and (rpc.get("error") or not rpc.get("response")):
                pass
            elif rpc.get("response"):
                await self._process_update(rpc["response"])

        if "update" in frame and frame["update"].get("update"):
            await self._process_update(frame["update"]["update"])

        if frame.get("terminateSession"):
            print("[WS] Session terminated by server")

    async def _subscribe(self):
        self.rpc_index += 1
        self.subscribe_idx = self.rpc_index
        await self.ws.send(encode_rpc_request(
            "bale.maviz.v1.MavizStream", "SubscribeToUpdates", b"", self.subscribe_idx
        ))

    def _start_ping(self):
        self._last_inbound_ts = time.time()

        async def ping_loop():
            while self.ready and self.ws:
                await asyncio.sleep(15)
                if not self.ready or not self.ws:
                    break
                idle = time.time() - self._last_inbound_ts
                if idle > 60:
                    print(f"[WS] No inbound for {idle:.0f}s - closing zombie connection")
                    try:
                        await self.ws.close()
                    except Exception:
                        pass
                    break
                if idle > 30:
                    print(f"[WS] idle {idle:.0f}s - no inbound")
                self.ping_counter += 1
                try:
                    await self.ws.send(encode_ping(self.ping_counter))
                except Exception as e:
                    print(f"[WS] ping send failed: {e}")
                    break

        self._ping_task = asyncio.create_task(ping_loop())

    def _start_set_online_loop(self):
        payload = bytes([0x08, 0x01, 0x10, 0x90, 0xF9, 0x05])

        async def online_loop():
            while self.ready:
                try:
                    await self._rpc_call("bale.presence.v1.Presence", "SetOnline", payload)
                except Exception as e:
                    print(f"[WS] SetOnline failed: {e}")
                await asyncio.sleep(90)

        self._online_task = asyncio.create_task(online_loop())

    async def _safe_call(self, cb, *args):
        try:
            await cb(*args)
        except Exception as e:
            print(f"[Update] callback threw: {e}")

    async def _process_update(self, buf: bytes):
        try:
            sub = decode_subscribe_response(buf)
        except Exception as e:
            print(f"[Update] decode error: {e}")
            return

        update = sub.get("update")
        if not update:
            return

        if update.get("callStarted") or update.get("callReceived"):
            call_id = (update.get("callReceived", {}).get("callId") or
                       update.get("callStarted", {}).get("call", {}).get("id"))
            kind = "callReceived" if update.get("callReceived") else "callStarted"
            call_entity = update.get("callStarted", {}).get("call")
            if not call_entity and update.get("callReceived"):
                call_entity = update.get("callReceived", {}).get("call")
            print(f"[Update] {kind} callId={call_id} callerId={call_entity.get('callerId') if call_entity else 'N/A'}")
            if call_id and call_id != "0":
                for cb in self._on_call_received[:]:
                    asyncio.create_task(self._safe_call(cb, call_id, call_entity))

        elif update.get("callAccepted"):
            call_id = update["callAccepted"].get("call", {}).get("id")
            print(f"[Update] callAccepted callId={call_id}")
            for cb in self._on_call_accepted[:]:
                try:
                    await cb(call_id)
                except Exception as e:
                    print(f"[Update] onCallAccepted subscriber threw: {e}")

        elif update.get("callEnded"):
            call_id = update["callEnded"]["callId"]
            print(f"[Update] callEnded callId={call_id}")
            for cb in self._on_call_ended[:]:
                try:
                    await cb(call_id)
                except Exception as e:
                    print(f"[Update] onCallEnded subscriber threw: {e}")

        elif update.get("message"):
            tif = update["message"]
            text = tif.get("message", {}).get("textMessage", {}).get("text", "")
            if text and self.tunnel:
                if self.tunnel.handle_incoming(text, tif.get("senderUid")):
                    return
                self.messages.append({
                    "dir": "in", "from": tif.get("senderUid"),
                    "rid": tif.get("rid"), "text": text, "ts": time.time()
                })

    async def _rpc_call(self, service: str, method: str, payload: bytes) -> bytes:
        if not self.ready:
            raise RuntimeError("Not connected")
        self.rpc_index += 1
        idx = self.rpc_index
        future = asyncio.get_event_loop().create_future()
        self._pending[idx] = {"future": future, "service": service, "method": method}
        await self.ws.send(encode_rpc_request(service, method, payload, idx))

        try:
            result = await asyncio.wait_for(future, timeout=15.0)
            return result
        except asyncio.TimeoutError:
            self._pending.pop(idx, None)
            raise RuntimeError("Timeout")

    async def discard_call(self, call_id):
        try:
            await self._rpc_call("bale.meet.v1.Meet", "DiscardCall", build_discard_call_request(call_id))
        except Exception as e:
            print(f"[DiscardCall] {call_id} failed: {e}")

    async def accept_call(self, call_id) -> dict:
        buf = await self._rpc_call("bale.meet.v1.Meet", "AcceptCall", build_accept_call_request(call_id))
        resp = decode_call_response(buf)
        print(f"[AcceptCall] call: {json.dumps({k: v for k, v in (resp.get('call') or {}).items() if k != 'token'}, default=str)}")
        return resp

    async def start_call(self, peer_id: int, peer_type: int) -> dict:
        rid = str(int(time.time() * 1000))
        buf = await self._rpc_call("bale.meet.v1.Meet", "StartCall",
                                   build_start_call_request(peer_id, peer_type, rid))
        return decode_call_response(buf)

    async def lookup_contact_name(self, uid: int) -> Optional[str]:
        n = int(uid)
        if n <= 0:
            return None
        if n in self._user_name_cache:
            return self._user_name_cache[n]
        name = None
        try:
            buf = await self._rpc_call(
                "bale.users.v1.Users", "LoadUsers",
                build_load_users_request([{"uid": n, "accessHash": "0"}])
            )
            loaded = decode_load_users_response(buf)
            if loaded["users"]:
                u = decode_user_entity(loaded["users"][0])
                name = u.get("name") or u.get("nick") or None
        except Exception as e:
            print(f"[lookupContactName] uid={n} RPC failed: {e}")
        self._user_name_cache[n] = name
        return name

    async def _load_self_safe(self):
        try:
            await self.load_self()
        except Exception as e:
            print(f"[Self] loadSelf failed: {e}")

    async def load_self(self):
        payload = decode_jwt_payload(self.access_token)
        if not payload:
            print("[Self] could not decode JWT payload")
            return None
        inner = payload.get("payload", {})
        uid = int(
            inner.get("user_id") or inner.get("userId") or inner.get("uid") or
            payload.get("user_id") or payload.get("userId") or payload.get("uid") or
            payload.get("sub") or payload.get("id") or 0
        )
        if not uid:
            print("[Self] no numeric user id in JWT")
            return None
        try:
            buf = await self._rpc_call(
                "bale.users.v1.Users", "LoadUsers",
                build_load_users_request([{"uid": uid, "accessHash": "0"}])
            )
            loaded = decode_load_users_response(buf)
            if not loaded["users"]:
                return None
            u = decode_user_entity(loaded["users"][0])
            self.self_info = {"id": u.get("id", uid), "name": u.get("name", ""), "nick": u.get("nick", "")}
            name_str = self.self_info["name"] or "(no name)"
            nick_str = f" @{self.self_info['nick']}" if self.self_info["nick"] else ""
            print(f"[Self] {name_str}{nick_str} ({self.self_info['id']})")
            return self.self_info
        except Exception as e:
            print(f"[Self] LoadUsers failed: {e}")
            return None

    async def _load_contacts_safe(self):
        try:
            await self.load_contacts()
        except Exception as e:
            print(f"[Contacts] loadContacts failed: {e}")

    async def load_contacts(self):
        contacts_buf = await self._rpc_call(
            "bale.users.v1.Users", "GetContacts", build_get_contacts_request()
        )
        contacts = decode_get_contacts_response(contacts_buf)

        peers = []
        if contacts["userPeers"]:
            load_buf = await self._rpc_call(
                "bale.users.v1.Users", "LoadUsers",
                build_load_users_request(contacts["userPeers"])
            )
            loaded = decode_load_users_response(load_buf)
            for b in loaded["users"]:
                u = decode_user_entity(b)
                if u.get("id"):
                    label = u.get("name", "") + (f" (@{u['nick']})" if u.get("nick") else "")
                    peers.append({"id": u["id"], "name": label, "type": PEERTYPE_PRIVATE})
            print(f"[Contacts] LoadUsers returned {len(peers)} users")
        elif contacts["users"]:
            for b in contacts["users"]:
                u = decode_user_entity(b)
                if u.get("id"):
                    label = u.get("name", "") + (f" (@{u['nick']})" if u.get("nick") else "")
                    peers.append({"id": u["id"], "name": label, "type": PEERTYPE_PRIVATE})
            print(f"[Contacts] Used inline users: {len(peers)}")

        peers.sort(key=lambda p: p["name"])
        self.peers = peers
        return peers

    async def send_text(self, peer_id: int, peer_type: int, text: str):
        if not self.ready:
            raise RuntimeError("Not connected to Bale")
        ex_peer_type = EXPEERTYPE_GROUP if peer_type == PEERTYPE_GROUP else EXPEERTYPE_PRIVATE
        rid = str(int(time.time() * 1000))
        payload = build_send_message_request(peer_id, peer_type, ex_peer_type, rid, text)
        await self._rpc_call("bale.messaging.v2.Messaging", "SendMessage", payload)
