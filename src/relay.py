import asyncio
import time
import socket
import struct
import os
import json
from typing import Optional, Callable
from settings import (
    PEERTYPE_PRIVATE, TUNNEL_PREFIX, CHUNK_SIZE, LK_CHUNK,
    CALL_ACCEPTED_TIMEOUT_S, PEER_TIMEOUT_S, PEER_JOIN_TIMEOUT_S,
    PENDING_TIMEOUT_S, PENDING_SWEEP_S,
    DEFAULT_LIMIT_KBPS, MAX_LIMIT_KBPS, THROTTLE_FLAG_S,
    MAX_CLIENTS_DEFAULT, MAX_CLIENTS_LIMIT,
)
from persistence import AdmissionStore, BlacklistStore, cfg_get
from transport import LiveKitTransport, lk_encode, lk_decode


def get_max_clients():
    v = int(cfg_get('maxClients', MAX_CLIENTS_DEFAULT) or MAX_CLIENTS_DEFAULT)
    return max(1, min(MAX_CLIENTS_LIMIT, v))


def make_sid():
    return os.urandom(6).hex()


def is_blocked_octets(a, b):
    return (
        a == 0 or a == 10 or
        (a == 100 and (b & 0xC0) == 64) or
        a == 127 or
        (a == 169 and b == 254) or
        (a == 172 and (b & 0xF0) == 16) or
        (a == 192 and b == 168) or
        a >= 224
    )


def is_blocked_dst(pkt):
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        return True
    return is_blocked_octets(pkt[16], pkt[17])


def is_blocked_ip4(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return True
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return True
    if any(n < 0 or n > 255 for n in nums):
        return True
    return is_blocked_octets(nums[0], nums[1])


async def resolve_and_check(host):
    if all(c.isdigit() or c == '.' for c in host):
        if is_blocked_ip4(host):
            raise RuntimeError(f'destination {host} blocked by egress filter')
        return host
    loop = asyncio.get_event_loop()
    try:
        infos = await loop.getaddrinfo(host, None, family=socket.AF_INET)
        if not infos:
            raise RuntimeError(f'DNS lookup failed for {host}')
        addr = infos[0][4][0]
    except socket.gaierror as e:
        raise RuntimeError(f'DNS lookup failed for {host}: {e}')
    if is_blocked_ip4(addr):
        raise RuntimeError(f'destination {host} ({addr}) blocked by egress filter')
    return addr


class TokenBucket:
    def __init__(self, rate_bps):
        self._rate = rate_bps
        self._cap = rate_bps
        self._tokens = float(rate_bps)
        self._last = time.time()
        self.last_drop = 0

    def set_rate(self, rate_bps):
        self._rate = rate_bps
        self._cap = rate_bps
        if self._tokens > self._cap:
            self._tokens = self._cap

    def take(self, nbytes):
        now = time.time()
        self._tokens = min(self._cap, self._tokens + (now - self._last) * self._rate)
        self._last = now
        if self._tokens < nbytes:
            self.last_drop = now
            return False
        self._tokens -= nbytes
        return True


def adjust_csum(pkt, off, old_hi, old_lo, new_hi, new_lo):
    s = ((~struct.unpack_from('>H', pkt, off)[0]) & 0xFFFF)
    s += (~old_hi & 0xFFFF) + (~old_lo & 0xFFFF) + new_hi + new_lo
    while s > 0xFFFF:
        s = (s & 0xFFFF) + (s >> 16)
    struct.pack_into('>H', pkt, off, ~s & 0xFFFF)


def rewrite_ip(pkt, field_offset, new_ip):
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        return
    parts = [int(x) for x in new_ip.split('.')]
    if (pkt[field_offset] == parts[0] and pkt[field_offset+1] == parts[1] and
        pkt[field_offset+2] == parts[2] and pkt[field_offset+3] == parts[3]):
        return
    old_hi = struct.unpack_from('>H', pkt, field_offset)[0]
    old_lo = struct.unpack_from('>H', pkt, field_offset + 2)[0]
    pkt[field_offset] = parts[0]
    pkt[field_offset+1] = parts[1]
    pkt[field_offset+2] = parts[2]
    pkt[field_offset+3] = parts[3]
    new_hi = (parts[0] << 8) | parts[1]
    new_lo = (parts[2] << 8) | parts[3]
    adjust_csum(pkt, 10, old_hi, old_lo, new_hi, new_lo)
    proto = pkt[9]
    ihl = (pkt[0] & 0x0F) * 4
    frag_info = struct.unpack_from('>H', pkt, 6)[0]
    if (frag_info & 0x1FFF) != 0:
        return
    if proto == 6 and len(pkt) >= ihl + 18:
        adjust_csum(pkt, ihl + 16, old_hi, old_lo, new_hi, new_lo)
    elif proto == 17 and len(pkt) >= ihl + 8:
        if struct.unpack_from('>H', pkt, ihl + 6)[0] != 0:
            adjust_csum(pkt, ihl + 6, old_hi, old_lo, new_hi, new_lo)


class TunnelManager:
    def __init__(self, get_bale=None, on_tunnel_ready=None, on_permanent_disconnect=None):
        self.get_bale = get_bale or (lambda: None)
        self.on_tunnel_ready = on_tunnel_ready or (lambda: None)
        self.on_permanent_disconnect = on_permanent_disconnect or (lambda: None)
        self.mode = None
        self.transport = 'webrtc'
        self.server_peer = None
        self.socks5_port = 1080
        self.socks5_srv = None
        self.sessions = {}
        self.lk_transport = None
        self.lk_rooms = {}
        self.pending_map = {}
        self._pending_sweep_task = None
        self._snat_pool = None
        self._snat_by_lk = {}
        self._lk_by_snat = {}
        self._caller_limits = {}
        for caller_id, lim in AdmissionStore.get_all_limits().items():
            if lim['upBps'] > 0 or lim['downBps'] > 0:
                self._caller_limits[caller_id] = lim
        self._call_id = None
        self._call_ids = set()
        self._call_ended_remover = None
        self._rejected = False
        self._gen = 0

    async def configure(self, mode, server_peer_id=0, server_peer_type=PEERTYPE_PRIVATE, socks5_port=1080, transport='webrtc'):
        await self._stop_all()
        self._rejected = False
        self.mode = mode
        self.transport = transport
        if mode == 'client':
            self.server_peer = {'id': int(server_peer_id), 'type': int(server_peer_type)} if server_peer_id else None
            self.socks5_port = int(socks5_port) or 1080
            if self.server_peer:
                await self._start_socks5()
                if self.transport == 'webrtc':
                    asyncio.create_task(self._start_webrtc_tunnel())
        elif mode == 'server':
            pass
        print(f'[Tunnel] mode={mode or "none"} transport={self.transport}')

    async def on_ws_ready(self):
        pass

    def handle_incoming(self, text, from_uid):
        if not text.startswith(TUNNEL_PREFIX):
            return False
        try:
            msg = json.loads(text[len(TUNNEL_PREFIX):])
        except (json.JSONDecodeError, ValueError):
            return False
        if self.mode == 'server':
            asyncio.create_task(self._srv_msg(msg, from_uid, None))
        elif self.mode == 'client':
            self._cli_msg(msg)
        return True

    async def on_call_received(self, call_id, call_entity):
        if self.mode != 'server':
            return
        call_key = str(call_id)
        caller_id = int((call_entity or {}).get('callerId', 0))
        if call_key in self.lk_rooms:
            return
        if not caller_id:
            print(f'[Tunnel/S] call {call_id} arrived without callerId - queuing as pending with uid=0')
            caller_name = None
            self.pending_map[call_key] = {
                'callId': call_key, 'callerId': 0,
                'callerName': caller_name, 'receivedAt': time.time(),
                '_entity': call_entity,
            }
            self._start_pending_sweep()
            return
        if BlacklistStore.is_blocked(caller_id):
            print(f'[Tunnel/S] rejecting blacklisted caller {caller_id}')
            ws = await self.get_bale()
            if ws:
                await ws.discard_call(call_id)
            return
        max_clients = get_max_clients()
        if len(self.lk_rooms) >= max_clients:
            print(f'[Tunnel/S] rejecting caller {caller_id} - at capacity')
            ws = await self.get_bale()
            if ws:
                await ws.discard_call(call_id)
            return
        if AdmissionStore.is_allowed(caller_id):
            self.pending_map.pop(call_key, None)
            await self._handle_call(call_id, caller_id, call_entity)
        else:
            for k, p in list(self.pending_map.items()):
                if p['callerId'] == caller_id:
                    self.pending_map.pop(k, None)
                    ws = await self.get_bale()
                    if ws:
                        await ws.discard_call(p['callId'])
                    break
            self.pending_map[call_key] = {
                'callId': call_key, 'callerId': caller_id,
                'callerName': None, 'receivedAt': time.time(),
                '_entity': call_entity,
            }
            self._start_pending_sweep()
            print(f'[Tunnel/S] call {call_id} from caller {caller_id} -> PENDING')

    def _start_pending_sweep(self):
        if self._pending_sweep_task and not self._pending_sweep_task.done():
            return
        async def sweep():
            while self.pending_map:
                await asyncio.sleep(PENDING_SWEEP_S)
                now = time.time()
                for k, p in list(self.pending_map.items()):
                    if now - p['receivedAt'] > PENDING_TIMEOUT_S:
                        await self.reject_pending(p['callId'])
        self._pending_sweep_task = asyncio.create_task(sweep())

    async def accept_pending(self, call_id, add_to_list=False):
        call_key = str(call_id)
        pending = self.pending_map.pop(call_key, None)
        if not pending:
            return False
        max_clients = get_max_clients()
        if len(self.lk_rooms) >= max_clients:
            ws = await self.get_bale()
            if ws:
                await ws.discard_call(call_id)
            return False
        if add_to_list and pending['callerId']:
            AdmissionStore.add(pending['callerId'])
        await self._handle_call(call_id, pending['callerId'], pending.get('_entity'))
        return True

    async def reject_pending(self, call_id, add_to_blacklist=False):
        call_key = str(call_id)
        pending = self.pending_map.pop(call_key, None)
        if not pending:
            return False
        ws = await self.get_bale()
        if ws:
            await ws.discard_call(call_id)
        if add_to_blacklist and pending['callerId']:
            BlacklistStore.add(pending['callerId'])
        return True

    def pending_calls(self):
        return [{'callId': p['callId'], 'callerId': p['callerId'],
                 'callerName': p.get('callerName'), 'receivedAt': p['receivedAt']}
                for p in self.pending_map.values()]

    def admission_list(self):
        return [{'callerId': cid} for cid in AdmissionStore.get_all()]

    def clients_list(self):
        result = []
        now = time.time()
        for call_key, lk in self.lk_rooms.items():
            throttled = False
            if lk._up_bucket and (now - lk._up_bucket.last_drop) < THROTTLE_FLAG_S:
                throttled = True
            if lk._down_bucket and (now - lk._down_bucket.last_drop) < THROTTLE_FLAG_S:
                throttled = True
            result.append({
                'callKey': call_key, 'callerId': lk._caller_id or 0,
                'callerName': lk._caller_name,
                'snatIp': self._snat_by_lk.get(id(lk)),
                'connectedAt': lk._connected_at,
                'rxPkts': lk._rx_pkts, 'rxBytes': lk._rx_bytes,
                'txPkts': lk._tx_pkts, 'txBytes': lk._tx_bytes,
                'throttled': throttled,
            })
        return result

    def _init_snat_pool(self):
        if self._snat_pool is not None:
            return
        self._snat_pool = []
        for i in range(2, 255):
            self._snat_pool.append(f'10.8.0.{i}')

    def _alloc_snat(self, lk):
        self._init_snat_pool()
        if not self._snat_pool:
            return None
        ip = self._snat_pool.pop(0)
        self._snat_by_lk[id(lk)] = ip
        self._lk_by_snat[ip] = lk
        return ip

    def _free_snat(self, lk):
        ip = self._snat_by_lk.pop(id(lk), None)
        if not ip:
            return
        self._lk_by_snat.pop(ip, None)
        if self._snat_pool is not None:
            self._snat_pool.append(ip)

    async def _handle_call(self, call_id, caller_id, call_entity):
        call_key = str(call_id)
        ws = await self.get_bale()
        if not ws:
            print('[Tunnel/S] AcceptCall: no WS available')
            return
        caller_name = None
        if caller_id:
            try:
                caller_name = await asyncio.wait_for(ws.lookup_contact_name(caller_id), timeout=3.0)
            except Exception:
                pass
        caller_label = f'{caller_name} ({caller_id})' if caller_name else f'caller {caller_id}'
        print(f'[Tunnel/S] Auto-answering call {call_id} from {caller_label}')
        resp = None
        for attempt in range(2):
            try:
                if attempt > 0:
                    ws = await self.get_bale()
                    if not ws:
                        print('[Tunnel/S] AcceptCall retry: no WS available')
                        return
                resp = await ws.accept_call(call_id)
                break
            except Exception as e:
                print(f'[Tunnel/S] AcceptCall failed (attempt {attempt+1}): {e}')
                if attempt == 0:
                    await asyncio.sleep(2)
        if not resp:
            return
        is_livekit = (call_entity or {}).get('isLivekit') or (resp.get('call') or {}).get('isLivekit')
        call = resp.get('call')
        if not caller_id and call:
            caller_id = call.get('callerId', 0)
            if caller_id:
                try:
                    caller_name = await ws.lookup_contact_name(caller_id)
                except Exception:
                    pass
                caller_label = f'{caller_name} ({caller_id})' if caller_name else f'caller {caller_id}'
                print(f'[Tunnel/S] Got callerId={caller_id} from AcceptCall response')
        if not is_livekit or not call or not call.get('token'):
            print('[Tunnel/S] Call answered - no LiveKit credentials')
            return
        if caller_id:
            for k, existing_lk in list(self.lk_rooms.items()):
                if existing_lk._caller_id == caller_id:
                    print(f'[Tunnel/S] replacing existing client {k} from caller {caller_id}')
                    existing_lk.disconnect()
        lk = LiveKitTransport()
        lk._call_key = call_key
        lk._caller_id = caller_id
        lk._caller_name = caller_name
        lk._connected_at = time.time()
        lk._rx_pkts = 0
        lk._rx_bytes = 0
        lk._tx_pkts = 0
        lk._tx_bytes = 0
        self.lk_rooms[call_key] = lk
        snat = self._alloc_snat(lk)
        if not snat:
            print(f'[Tunnel/S] SNAT pool exhausted')
            del self.lk_rooms[call_key]
            await ws.discard_call(call_id)
            return
        print(f'[Tunnel/S] SNAT lease {snat} for callKey={call_key} caller={caller_id}')
        default_bps = DEFAULT_LIMIT_KBPS * 1000 // 8
        override = self._caller_limits.get(caller_id) if caller_id else None
        lk._up_bucket = TokenBucket((override or {}).get('upBps') or default_bps)
        lk._down_bucket = TokenBucket((override or {}).get('downBps') or default_bps)
        def on_data(data):
            lk._rx_pkts += 1
            lk._rx_bytes += len(data)
            msg = lk_decode(data)
            if msg and msg['t'] == 'I':
                pass
            elif msg:
                asyncio.create_task(self._srv_msg(msg, call_key, lk))
        lk.on_data = on_data
        def on_disconnected():
            self.lk_rooms.pop(call_key, None)
            self._free_snat(lk)
            closed = 0
            for key in list(self.sessions.keys()):
                sess = self.sessions[key]
                if sess.get('lk') is lk:
                    sess['dead'] = True
                    if sess.get('writer'):
                        sess['writer'].close()
                    del self.sessions[key]
                    closed += 1
            who = f'{lk._caller_name} ({lk._caller_id})' if lk._caller_name else f'caller {lk._caller_id}'
            print(f'[Tunnel/S] {who} disconnected callKey={call_key} closed={closed} session(s)')
        lk.on_disconnected = on_disconnected
        try:
            await lk.connect(call['url'], call['token'])
        except Exception as e:
            print(f'[Tunnel/S] LiveKit connect failed: {e}')
            self.lk_rooms.pop(call_key, None)
            self._free_snat(lk)
            return
        async def peer_watchdog():
            await asyncio.sleep(PEER_JOIN_TIMEOUT_S)
            cur = self.lk_rooms.get(call_key)
            if cur is lk and not lk.has_peer:
                print(f'[Tunnel/S] peer never joined call {call_id} - disconnecting')
                lk.disconnect()
                ws2 = await self.get_bale()
                if ws2:
                    await ws2.discard_call(call_id)
        asyncio.create_task(peer_watchdog())

    def disconnect_client(self, call_key):
        lk = self.lk_rooms.get(call_key)
        if not lk:
            return False
        lk.disconnect()
        return True

    async def disconnect_all_clients(self, ws):
        if self.mode != 'server':
            return
        for p in self.pending_map.values():
            if ws and ws.ready:
                await ws.discard_call(p['callId'])
        self.pending_map.clear()
        for call_key, lk in list(self.lk_rooms.items()):
            if ws and ws.ready:
                await ws.discard_call(call_key)
            lk.disconnect()
        self.lk_rooms.clear()

    async def _start_webrtc_tunnel(self):
        if self.mode != 'client' or not self.server_peer:
            return
        gen = self._gen + 1
        self._gen = gen
        def cancelled():
            return gen != self._gen
        def fail(reason):
            print(f'[Tunnel/C] connect failed - {reason}')
            asyncio.create_task(self._stop_all())
            try:
                self.on_permanent_disconnect()
            except Exception:
                pass
        if self.lk_transport:
            prev = self.lk_transport
            self.lk_transport = None
            prev.disconnect()
        ws = await self.get_bale()
        if cancelled():
            return
        if not ws:
            fail('WS unavailable')
            return
        print('[Tunnel/C] Starting call for WebRTC tunnel...')
        try:
            resp = await ws.start_call(self.server_peer['id'], self.server_peer['type'])
        except Exception as e:
            fail(f'StartCall: {e}')
            return
        if cancelled():
            return
        call = resp.get('call')
        if not call or not call.get('isLivekit') or not call.get('token'):
            fail('StartCall: no LiveKit info in response')
            return
        self._call_id = call['id']
        self._call_ids.clear()
        self._call_ids.add(str(call['id']))
        if self._call_ended_remover:
            self._call_ended_remover()
            self._call_ended_remover = None
        async def on_call_ended(ended_id):
            if str(ended_id) in self._call_ids:
                print(f'[Tunnel/C] Peer ended call {ended_id} - server rejected')
                self._rejected = True
                await self._stop_all()
                try:
                    self.on_permanent_disconnect()
                except Exception:
                    pass
        self._call_ended_remover = ws.add_on_call_ended(on_call_ended)
        print('[Tunnel/C] Waiting for callAccepted...')
        accepted_event = asyncio.Event()
        async def on_accepted(accepted_id):
            if str(accepted_id) == str(call['id']):
                accepted_event.set()
        accepted_remover = ws.add_on_call_accepted(on_accepted)
        try:
            await asyncio.wait_for(accepted_event.wait(), timeout=CALL_ACCEPTED_TIMEOUT_S)
            accepted = True
        except asyncio.TimeoutError:
            accepted = False
        finally:
            accepted_remover()
        if cancelled():
            return
        if not accepted:
            fail(f'callAccepted timeout after {CALL_ACCEPTED_TIMEOUT_S}s')
            return
        print(f'[Tunnel/C] callAccepted - joining LiveKit room {call["room"]}')
        lk = LiveKitTransport()
        lk._rx_pkts = 0
        lk._rx_bytes = 0
        lk._tx_pkts = 0
        lk._tx_bytes = 0
        def on_data(data):
            lk._rx_pkts += 1
            lk._rx_bytes += len(data)
            msg = lk_decode(data)
            if msg and msg['t'] != 'I':
                self._cli_msg(msg)
        lk.on_data = on_data
        def on_lk_disconnected():
            if self.lk_transport is lk:
                self.lk_transport = None
                print('[Tunnel/C] LiveKit disconnected - permanent disconnect')
                self._close_cli_sessions()
                asyncio.create_task(self._stop_all())
                try:
                    self.on_permanent_disconnect()
                except Exception:
                    pass
        lk.on_disconnected = on_lk_disconnected
        try:
            await lk.connect(call['url'], call['token'])
        except Exception as e:
            fail(f'LiveKit connect: {e}')
            return
        if cancelled():
            lk.disconnect()
            return
        deadline = time.time() + PEER_TIMEOUT_S
        while not lk.has_peer and lk.room and time.time() < deadline:
            await asyncio.sleep(0.2)
            if cancelled():
                lk.disconnect()
                return
        if not lk.has_peer:
            if lk.room:
                lk.disconnect()
            fail(f'peer never joined after {PEER_TIMEOUT_S}s')
            return
        self.lk_transport = lk
        print('[Tunnel/C] WebRTC tunnel ready')
        try:
            self.on_tunnel_ready()
        except Exception as e:
            print(f'[Tunnel/C] on_tunnel_ready threw: {e}')

    def _close_cli_sessions(self):
        closed = 0
        for key in list(self.sessions.keys()):
            sess = self.sessions[key]
            sess['dead'] = True
            if sess.get('writer'):
                try:
                    sess['writer'].close()
                except Exception:
                    pass
            del self.sessions[key]
            closed += 1
        if closed:
            print(f'[Tunnel/C] Closed {closed} SOCKS5 session(s)')

    async def _start_socks5(self):
        async def handle_client(reader, writer):
            try:
                await self._handle_socks5(reader, writer)
            except Exception:
                writer.close()
        self.socks5_srv = await asyncio.start_server(
            handle_client, '0.0.0.0', self.socks5_port)
        print(f'[SOCKS5] 0.0.0.0:{self.socks5_port}')

    async def _handle_socks5(self, reader, writer):
        greeting = await reader.read(256)
        if not greeting or greeting[0] != 0x05:
            writer.close()
            return
        writer.write(bytes([0x05, 0x00]))
        await writer.drain()
        req = await reader.read(512)
        if not req or req[0] != 0x05 or req[1] != 0x01:
            writer.write(bytes([0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0]))
            writer.close()
            return
        host = None
        port = 0
        atyp = req[3]
        if atyp == 0x01:
            host = f'{req[4]}.{req[5]}.{req[6]}.{req[7]}'
            port = struct.unpack('>H', req[8:10])[0]
        elif atyp == 0x03:
            hlen = req[4]
            host = req[5:5+hlen].decode('utf-8')
            port = struct.unpack('>H', req[5+hlen:7+hlen])[0]
        elif atyp == 0x04:
            writer.write(bytes([0x05, 0x08, 0x00, 0x01, 0,0,0,0, 0,0]))
            writer.close()
            return
        else:
            writer.write(bytes([0x05, 0x08, 0x00, 0x01, 0,0,0,0, 0,0]))
            writer.close()
            return
        if not self.server_peer:
            writer.write(bytes([0x05, 0x01, 0x00, 0x01, 0,0,0,0, 0,0]))
            writer.close()
            return
        sid = make_sid()
        sess = {'sid': sid, 'writer': writer, 'reader': reader, 'tx_seq': 0,
                'rx_buf': {}, 'rx_next': 0, 'ready': False, 'queue': [], 'dead': False}
        self.sessions[sid] = sess
        print(f'[Tunnel/C] {sid} CONNECT {host}:{port}')
        await self._cli_send({'t': 'C', 's': sid, 'h': host, 'p': port})
        async def read_loop():
            try:
                while not sess['dead']:
                    chunk = await reader.read(LK_CHUNK)
                    if not chunk:
                        break
                    if not sess['ready']:
                        sess['queue'].append(chunk)
                        continue
                    for i in range(0, len(chunk), LK_CHUNK):
                        sl = chunk[i:i+LK_CHUNK]
                        await self._cli_send({'t': 'D', 's': sid, 'data': sl})
            except Exception:
                pass
            finally:
                await self._cli_close(sid)
        asyncio.create_task(read_loop())

    def _cli_msg(self, msg):
        t = msg.get('t')
        sid = msg.get('s')
        sess = self.sessions.get(sid)
        if not sess:
            return
        if t == 'A':
            if msg.get('ok'):
                sess['writer'].write(bytes([0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]))
                sess['ready'] = True
                for chunk in sess['queue']:
                    for i in range(0, len(chunk), LK_CHUNK):
                        sl = chunk[i:i+LK_CHUNK]
                        asyncio.create_task(self._cli_send({'t': 'D', 's': sid, 'data': sl}))
                sess['queue'] = []
            else:
                sess['writer'].write(bytes([0x05, 0x05, 0x00, 0x01, 0,0,0,0, 0,0]))
                sess['dead'] = True
                sess['writer'].close()
                self.sessions.pop(sid, None)
        elif t == 'D':
            data = msg.get('data')
            if data and not sess['writer'].is_closing():
                sess['writer'].write(data)
        elif t == 'X':
            sess['dead'] = True
            try:
                sess['writer'].close()
            except Exception:
                pass
            self.sessions.pop(sid, None)

    async def _cli_close(self, sid):
        sess = self.sessions.get(sid)
        if not sess or sess['dead']:
            return
        sess['dead'] = True
        await self._cli_send({'t': 'X', 's': sid})
        self.sessions.pop(sid, None)

    async def _cli_send(self, obj):
        if self.transport == 'webrtc':
            if self.lk_transport:
                encoded = lk_encode(obj)
                self.lk_transport._tx_pkts += 1
                self.lk_transport._tx_bytes += len(encoded)
                await self.lk_transport.send(encoded)
        elif self.server_peer:
            ws = await self.get_bale()
            if ws:
                text = TUNNEL_PREFIX + json.dumps(obj, separators=(',', ':'))
                await ws.send_text(self.server_peer['id'], self.server_peer['type'], text)

    async def _srv_msg(self, msg, from_key, lk):
        t = msg.get('t')
        sid = msg.get('s', '')
        key = f'{from_key}:{sid}'
        if t == 'C':
            host = msg.get('h', '')
            port = msg.get('p', 0)
            print(f'[Tunnel/S] {key} TCP -> {host}:{port}')
            sess = {'key': key, 'host': host, 'port': port, 'writer': None,
                    'reader': None, 'from_uid': None if lk else int(from_key),
                    'lk': lk, 'tx_seq': 0, 'dead': False, 'tx_bytes': 0, 'rx_bytes': 0}
            self.sessions[key] = sess
            try:
                addr = await resolve_and_check(host)
            except RuntimeError as e:
                print(f'[Tunnel/S] {key} TCP x {host}:{port} - {e}')
                await self._srv_send(sess, {'t': 'A', 's': sid, 'ok': False})
                self.sessions.pop(key, None)
                return
            try:
                reader, writer = await asyncio.open_connection(addr, port)
            except Exception as e:
                print(f'[Tunnel/S] {key} TCP x {host}:{port} - {e}')
                await self._srv_send(sess, {'t': 'A', 's': sid, 'ok': False})
                self.sessions.pop(key, None)
                return
            if sess['dead']:
                writer.close()
                return
            sess['writer'] = writer
            sess['reader'] = reader
            print(f'[Tunnel/S] {key} TCP ok {host}:{port}')
            await self._srv_send(sess, {'t': 'A', 's': sid, 'ok': True})
            async def relay_loop():
                try:
                    while not sess['dead']:
                        chunk = await reader.read(LK_CHUNK)
                        if not chunk:
                            break
                        sess['rx_bytes'] += len(chunk)
                        if sess['lk']:
                            for i in range(0, len(chunk), LK_CHUNK):
                                frame = lk_encode({'t': 'D', 's': sid, 'data': chunk[i:i+LK_CHUNK]})
                                sess['lk']._tx_pkts += 1
                                sess['lk']._tx_bytes += len(frame)
                                await sess['lk'].send(frame)
                        else:
                            for i in range(0, len(chunk), CHUNK_SIZE):
                                import base64
                                sl = chunk[i:i+CHUNK_SIZE]
                                await self._srv_send(sess, {'t': 'D', 's': sid, 'q': sess['tx_seq'], 'd': base64.b64encode(sl).decode()})
                                sess['tx_seq'] += 1
                except Exception:
                    pass
                finally:
                    await self._srv_close(key, sid, 'remote end')
            asyncio.create_task(relay_loop())
        elif t == 'D':
            sess = self.sessions.get(key)
            if not sess or sess['dead']:
                return
            if not sess['writer'] or sess['writer'].is_closing():
                return
            data = msg.get('data')
            if data:
                sess['tx_bytes'] += len(data)
                sess['writer'].write(data)
            else:
                import base64
                buf = base64.b64decode(msg.get('d', ''))
                sess['tx_bytes'] += len(buf)
                sess['writer'].write(buf)
        elif t == 'X':
            sess = self.sessions.get(key)
            if sess:
                sess['dead'] = True
                if sess.get('writer'):
                    sess['writer'].close()
                self.sessions.pop(key, None)
                print(f'[Tunnel/S] {key} TCP x {sess["host"]}:{sess["port"]} (client)')

    async def _srv_close(self, key, sid, reason='unknown'):
        sess = self.sessions.get(key)
        if not sess or sess['dead']:
            return
        sess['dead'] = True
        if sess.get('lk'):
            xframe = lk_encode({'t': 'X', 's': sid})
            sess['lk']._tx_pkts += 1
            sess['lk']._tx_bytes += len(xframe)
            await sess['lk'].send(xframe)
        else:
            ws = await self.get_bale()
            if ws:
                text = TUNNEL_PREFIX + json.dumps({'t': 'X', 's': sid}, separators=(',', ':'))
                await ws.send_text(sess['from_uid'], PEERTYPE_PRIVATE, text)
        self.sessions.pop(key, None)
        print(f'[Tunnel/S] {key} TCP x {sess["host"]}:{sess["port"]} ({reason})')

    async def _srv_send(self, sess, obj):
        if sess.get('lk'):
            encoded = lk_encode(obj)
            sess['lk']._tx_pkts += 1
            sess['lk']._tx_bytes += len(encoded)
            if obj.get('t') in ('A', 'U'):
                await sess['lk'].send_urgent(encoded)
            else:
                await sess['lk'].send(encoded)
        else:
            ws = await self.get_bale()
            if ws:
                text = TUNNEL_PREFIX + json.dumps(obj, separators=(',', ':'))
                await ws.send_text(sess['from_uid'], PEERTYPE_PRIVATE, text)

    async def _stop_all(self):
        self._gen += 1
        self._call_ids.clear()
        if self._call_ended_remover:
            self._call_ended_remover()
            self._call_ended_remover = None
        self._call_id = None
        self.mode = None
        self.server_peer = None
        if self.socks5_srv:
            self.socks5_srv.close()
            self.socks5_srv = None
        if self.lk_transport:
            lk = self.lk_transport
            self.lk_transport = None
            lk.disconnect()
        for lk in list(self.lk_rooms.values()):
            lk.disconnect()
        self.lk_rooms.clear()
        for sess in self.sessions.values():
            sess['dead'] = True
            if sess.get('writer'):
                try:
                    sess['writer'].close()
                except Exception:
                    pass
        self.sessions.clear()
        for lk_ref in list(self._snat_by_lk.keys()):
            self._snat_by_lk.pop(lk_ref, None)
        self._lk_by_snat.clear()
