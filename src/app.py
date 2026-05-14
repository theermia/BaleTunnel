import asyncio
import sys
import time
import os
import signal
from pathlib import Path

sys.path.insert(0, str(Path(os.path.abspath(__file__)).parent))

_ca_bundle = str(Path(os.path.abspath(__file__)).parent / "ca_bundle.pem")
if os.path.exists(_ca_bundle):
    os.environ["SSL_CERT_FILE"] = _ca_bundle
    os.environ["SSL_CERT_DIR"] = ""

from settings import (
    PEERTYPE_PRIVATE, PEERTYPE_GROUP, MAX_LIMIT_KBPS,
    MAX_CLIENTS_DEFAULT, MAX_CLIENTS_LIMIT,
)
from persistence import AdmissionStore, BlacklistStore, cfg_get, cfg_set
from rpc import grpc_call, fetch_access_token, GrpcError
from protocol import (
    build_start_phone_auth_request, decode_start_phone_auth_response,
    build_validate_code_request, decode_auth_response, build_signup_request,
)
from ws_client import BaleWsClient
from relay import TunnelManager


def ts():
    from datetime import datetime
    return datetime.now().strftime('%H:%M:%S.%f')[:-3]


_orig_print = print
def patched_print(*args, **kwargs):
    _orig_print(f'[{ts()}]', *args, **kwargs)


import builtins
builtins.print = patched_print


class BaleConnection:
    def __init__(self, mode):
        self.mode = mode
        self.client = None
        self.user_initiated_disconnect = False

    @property
    def is_ready(self):
        return self.client and self.client.ready

    @property
    def is_up(self):
        return self.client and (self.client.connecting or self.client.ready)

    def _desired_up(self):
        if self.user_initiated_disconnect:
            return False
        if self.mode == 'server':
            return True
        t = self.client.tunnel
        if t and t.mode == 'client' and t.lk_transport:
            return False
        return True

    async def reconcile(self):
        want = bool(self.client.access_token) and self._desired_up()
        if want and not self.is_up:
            await self.client.connect()
        elif not want and self.is_up:
            await self.client.disconnect()

    async def resolve_ws(self):
        if not self.client.access_token:
            return None
        self.user_initiated_disconnect = False
        if not self.is_up:
            await self.client.connect()
        if not self.client.ready:
            for _ in range(40):
                if self.client.ready:
                    break
                await asyncio.sleep(0.5)
        return self.client if self.client.ready else None

    def on_tunnel_permanent_disconnect(self):
        print('[BaleConnection] tunnel permanent disconnect - reconciling WS')
        asyncio.create_task(self.reconcile())


class CLI:
    def __init__(self, mode):
        self.mode = mode
        self.connection = BaleConnection(mode)
        self.client = BaleWsClient()
        self.connection.client = self.client
        self.tunnel = TunnelManager(
            get_bale=self.connection.resolve_ws,
            on_tunnel_ready=lambda: asyncio.create_task(self.connection.reconcile()),
            on_permanent_disconnect=self.connection.on_tunnel_permanent_disconnect,
        )
        self.client.tunnel = self.tunnel
        async def on_call_received(call_id, call_entity):
            await self.tunnel.on_call_received(call_id, call_entity)
        async def on_call_ended(call_id):
            call_key = str(call_id)
            if call_key in self.tunnel.pending_map:
                self.tunnel.pending_map.pop(call_key, None)
            if call_key in self.tunnel.lk_rooms:
                self.tunnel.disconnect_client(call_key)
        self.client.add_on_call_received(on_call_received)
        self.client.add_on_call_ended(on_call_ended)

    async def run(self):
        print(f'BaleVPN Python - Mode: {self.mode}')
        print('Type "help" for available commands')
        print('')
        if self.mode == 'server':
            await self.tunnel.configure('server')
        await self.connection.reconcile()
        await self._input_loop()

    async def _input_loop(self):
        loop = asyncio.get_event_loop()
        while True:
            try:
                line = await loop.run_in_executor(None, lambda: input('> '))
                line = line.strip()
                if not line:
                    continue
                await self._handle_command(line)
            except (EOFError, KeyboardInterrupt):
                print('\nExiting...')
                await self._shutdown()
                break
            except Exception as e:
                print(f'Error: {e}')

    async def _handle_command(self, line):
        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]
        if cmd == 'help':
            self._print_help()
        elif cmd == 'login':
            await self._cmd_login()
        elif cmd == 'logout':
            await self._cmd_logout()
        elif cmd == 'status':
            self._cmd_status()
        elif cmd == 'peers':
            await self._cmd_peers()
        elif cmd == 'connect' and self.mode == 'client':
            await self._cmd_connect(args)
        elif cmd == 'disconnect':
            await self._cmd_disconnect()
        elif cmd == 'pending' and self.mode == 'server':
            self._cmd_pending()
        elif cmd == 'accept' and self.mode == 'server':
            await self._cmd_accept(args)
        elif cmd == 'reject' and self.mode == 'server':
            await self._cmd_reject(args)
        elif cmd == 'clients' and self.mode == 'server':
            self._cmd_clients()
        elif cmd == 'kick' and self.mode == 'server':
            self._cmd_kick(args)
        elif cmd == 'allow' and self.mode == 'server':
            self._cmd_allow(args)
        elif cmd == 'block' and self.mode == 'server':
            self._cmd_block(args)
        elif cmd == 'unblock' and self.mode == 'server':
            self._cmd_unblock(args)
        elif cmd == 'admission' and self.mode == 'server':
            self._cmd_admission()
        elif cmd == 'blacklist' and self.mode == 'server':
            self._cmd_blacklist()
        elif cmd == 'exit' or cmd == 'quit':
            print('Exiting...')
            await self._shutdown()
            raise SystemExit(0)
        else:
            print(f'Unknown command: {cmd}. Type "help" for available commands.')

    def _print_help(self):
        print('Available commands:')
        print('  login          - Login with phone number')
        print('  logout         - Logout and clear token')
        print('  status         - Show connection status')
        print('  peers          - List contacts')
        if self.mode == 'client':
            print('  connect <id>   - Connect to server peer by ID')
            print('  disconnect     - Disconnect tunnel')
        else:
            print('  disconnect     - Disconnect all clients')
            print('  pending        - Show pending calls')
            print('  accept <id>    - Accept pending call')
            print('  reject <id>    - Reject pending call')
            print('  clients        - Show connected clients')
            print('  kick <key>     - Kick a connected client')
            print('  allow <uid>    - Add user to allow-list')
            print('  block <uid>    - Block a user')
            print('  unblock <uid>  - Unblock a user')
            print('  admission      - Show allow-list')
            print('  blacklist      - Show block-list')
        print('  exit/quit      - Exit the program')

    async def _cmd_login(self):
        loop = asyncio.get_event_loop()
        if self.client.access_token:
            print('Already logged in. Use "logout" first.')
            return
        phone = await loop.run_in_executor(None, lambda: input('Phone number (e.g. +98912...): '))
        phone = phone.strip()
        if not phone:
            print('Cancelled.')
            return
        try:
            buf = grpc_call('bale.auth.v1.Auth', 'StartPhoneAuth', build_start_phone_auth_request(phone))
            resp = decode_start_phone_auth_response(buf)
            print(f'Code sent. Registered: {resp["isRegistered"]}')
        except Exception as e:
            print(f'StartPhoneAuth failed: {e}')
            return
        code = await loop.run_in_executor(None, lambda: input('Enter verification code: '))
        code = code.strip()
        if not code:
            print('Cancelled.')
            return
        try:
            buf = grpc_call('bale.auth.v1.Auth', 'ValidateCode',
                           build_validate_code_request(resp['transactionHash'], code))
            auth_resp = decode_auth_response(buf)
        except GrpcError as e:
            if 'PHONE_NUMBER_UNOCCUPIED' in str(e):
                name = await loop.run_in_executor(None, lambda: input('New account. Enter your name: '))
                name = name.strip()
                if not name:
                    print('Cancelled.')
                    return
                buf = grpc_call('bale.auth.v1.Auth', 'SignUp',
                               build_signup_request(resp['transactionHash'], name))
                auth_resp = decode_auth_response(buf)
            else:
                print(f'ValidateCode failed: {e}')
                return
        except Exception as e:
            print(f'ValidateCode failed: {e}')
            return
        jwt = auth_resp.get('jwt')
        if not jwt:
            print('No JWT in response')
            return
        token = fetch_access_token(jwt) or jwt
        print('Login successful.')
        self.client.access_token = token
        self.connection.user_initiated_disconnect = False
        await self.connection.reconcile()

    async def _cmd_logout(self):
        self.connection.user_initiated_disconnect = True
        if self.mode == 'server':
            await self.tunnel.disconnect_all_clients(self.client)
        else:
            await self.tunnel._stop_all()
        await self.client.disconnect()
        self.client.access_token = ''
        self.client.self_info = None
        print('Logged out.')

    def _cmd_status(self):
        print(f'  Mode:       {self.mode}')
        print(f'  Logged in:  {bool(self.client.access_token)}')
        if self.client.self_info:
            s = self.client.self_info
            print(f'  User:       {s.get("name", "")} ({s.get("id", "")})')
        print(f'  WS Ready:   {self.client.ready}')
        print(f'  WS Connecting: {self.client.connecting}')
        if self.client.session_expired:
            print('  WARNING: Session expired - please login again')
        if self.mode == 'client':
            lk = self.tunnel.lk_transport
            print(f'  Tunnel:     {"connected" if lk and lk.has_peer else "not connected"}')
            if lk:
                print(f'  RX: {lk._rx_bytes} bytes  TX: {lk._tx_bytes} bytes')
            print(f'  SOCKS5:     127.0.0.1:{self.tunnel.socks5_port}')
            print(f'  Sessions:   {len(self.tunnel.sessions)}')
        else:
            print(f'  Clients:    {len(self.tunnel.lk_rooms)}')
            print(f'  Pending:    {len(self.tunnel.pending_map)}')
            print(f'  Sessions:   {len(self.tunnel.sessions)}')

    async def _cmd_peers(self):
        if not self.client.ready:
            print('Not connected to Bale.')
            return
        await self.client.load_contacts()
        if not self.client.peers:
            print('No contacts found.')
            return
        print(f'Contacts ({len(self.client.peers)}):')
        for p in self.client.peers:
            print(f'  [{p["id"]}] {p["name"]}')

    async def _cmd_connect(self, args):
        if not self.client.access_token:
            print('Not logged in. Use "login" first.')
            return
        if not args:
            print('Usage: connect <peer_id>')
            return
        peer_id = int(args[0])
        print(f'Connecting to peer {peer_id}...')
        await self.tunnel.configure('client', server_peer_id=peer_id,
                                   server_peer_type=PEERTYPE_PRIVATE,
                                   socks5_port=self.tunnel.socks5_port)

    async def _cmd_disconnect(self):
        if self.mode == 'server':
            self.connection.user_initiated_disconnect = True
            await self.tunnel.disconnect_all_clients(self.client)
        else:
            await self.tunnel._stop_all()
        await self.connection.reconcile()
        print('Disconnected.')

    def _cmd_pending(self):
        pending = self.tunnel.pending_calls()
        if not pending:
            print('No pending calls.')
            return
        print(f'Pending calls ({len(pending)}):')
        for p in pending:
            name = p.get('callerName') or 'unknown'
            print(f'  Call {p["callId"]} from {name} (uid={p["callerId"]})')

    async def _cmd_accept(self, args):
        if not args:
            print('Usage: accept <call_id> [--save]')
            return
        call_id = args[0]
        add_to_list = '--save' in args
        ok = await self.tunnel.accept_pending(call_id, add_to_list)
        print(f'Accept: {"ok" if ok else "failed"}')

    async def _cmd_reject(self, args):
        if not args:
            print('Usage: reject <call_id> [--block]')
            return
        call_id = args[0]
        block = '--block' in args
        ok = await self.tunnel.reject_pending(call_id, block)
        print(f'Reject: {"ok" if ok else "failed"}')

    def _cmd_clients(self):
        clients = self.tunnel.clients_list()
        if not clients:
            print('No connected clients.')
            return
        print(f'Connected clients ({len(clients)}):')
        for c in clients:
            name = c.get('callerName') or 'unknown'
            print(f'  [{c["callKey"]}] {name} (uid={c["callerId"]}) rx={c["rxBytes"]}B tx={c["txBytes"]}B')

    def _cmd_kick(self, args):
        if not args:
            print('Usage: kick <call_key>')
            return
        ok = self.tunnel.disconnect_client(args[0])
        print(f'Kick: {"ok" if ok else "not found"}')

    def _cmd_allow(self, args):
        if not args:
            print('Usage: allow <uid>')
            return
        ok = AdmissionStore.add(int(args[0]))
        print(f'Allow: {"added" if ok else "already in list"}')

    def _cmd_block(self, args):
        if not args:
            print('Usage: block <uid>')
            return
        ok = BlacklistStore.add(int(args[0]))
        print(f'Block: {"added" if ok else "already blocked"}')

    def _cmd_unblock(self, args):
        if not args:
            print('Usage: unblock <uid>')
            return
        ok = BlacklistStore.remove(int(args[0]))
        print(f'Unblock: {"removed" if ok else "not in list"}')

    def _cmd_admission(self):
        entries = AdmissionStore.get_all()
        if not entries:
            print('Allow-list is empty.')
            return
        print(f'Allow-list ({len(entries)}):')
        for uid in entries:
            lim = AdmissionStore.get_limit(uid)
            extra = ''
            if lim and (lim['upBps'] or lim['downBps']):
                extra = f' (up={lim["upBps"]}Bps down={lim["downBps"]}Bps)'
            print(f'  uid={uid}{extra}')

    def _cmd_blacklist(self):
        entries = BlacklistStore.get_all()
        if not entries:
            print('Block-list is empty.')
            return
        print(f'Block-list ({len(entries)}):')
        for uid in entries:
            print(f'  uid={uid}')

    async def _shutdown(self):
        try:
            await self.tunnel._stop_all()
        except Exception:
            pass
        try:
            await self.client.disconnect()
        except Exception:
            pass


async def main():
    from settings import parse_args
    args = parse_args()
    cli = CLI(args.mode)
    cli.tunnel.socks5_port = args.port
    if args.peer_id and args.mode == 'client':
        cli.tunnel.server_peer = {'id': args.peer_id, 'type': args.peer_type}
    await cli.run()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
