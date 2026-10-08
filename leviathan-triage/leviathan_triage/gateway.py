"""Discord gateway bot over a hand-rolled RFC 6455 WebSocket client.

Why hand-rolled: this package ships ZERO third-party dependencies (same
discipline as hostage). Python's stdlib has no WebSocket client, so here it
is - client frames are masked per RFC 6455, server frames are parsed with
full 126/127-bit length + continuation support, the Sec-WebSocket-Accept is
verified, and the Discord session layer implements identify, resume,
heartbeat/ack tracking, and exponential backoff.

Slash commands only => intents = 0 (no privileged intents, no message
content access - the bot never reads normal chat).

Everything is injectable for tests: socket_factory, sleep, now, transport.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import time
from typing import Callable, Optional

from . import config
from .http import http_get, http_post_json, http_put_json, TransportError

API_BASE = "https://discord.com/api/v10"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# WebSocket opcodes
WS_TEXT, WS_BINARY, WS_CLOSE, WS_PING, WS_PONG = 0x1, 0x2, 0x8, 0x9, 0xA

# Discord gateway opcodes
OP_DISPATCH, OP_HEARTBEAT, OP_IDENTIFY = 0, 1, 2
OP_RESUME, OP_RECONNECT, OP_INVALID_SESSION = 6, 7, 9
OP_HELLO, OP_HEARTBEAT_ACK = 10, 11


class ConnectionClosed(Exception):
    def __init__(self, code: int = 0, reason: str = ""):
        super().__init__(f"connection closed ({code}) {reason}")
        self.code = code
        self.reason = reason


class ReconnectNeeded(Exception):
    pass


class FatalAuthError(Exception):
    pass


# --------------------------------------------------------------------- frames
def build_client_frame(opcode: int, payload: bytes, mask: bytes,
                       fin: bool = True) -> bytes:
    """Client->server frames MUST be masked (RFC 6455 5.3)."""
    if len(mask) != 4:
        raise ValueError("mask must be 4 bytes")
    b0 = (0x80 if fin else 0x00) | opcode
    n = len(payload)
    if n < 126:
        header = struct.pack("!BB", b0, 0x80 | n)
    elif n < 65536:
        header = struct.pack("!BBH", b0, 0x80 | 126, n)
    else:
        header = struct.pack("!BBQ", b0, 0x80 | 127, n)
    masked = bytes(payload[i] ^ mask[i % 4] for i in range(n))
    return header + mask + masked


def parse_ws_frame(recv_exact: Callable) -> tuple:
    """-> (fin, opcode, payload). Handles extended lengths and masking."""
    head = recv_exact(2)
    b0, b1 = head[0], head[1]
    fin, opcode = bool(b0 & 0x80), b0 & 0x0F
    masked, length = bool(b1 & 0x80), b1 & 0x7F
    if length == 126:
        length = struct.unpack("!H", recv_exact(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(8))[0]
    mask_key = recv_exact(4) if masked else b""
    payload = recv_exact(length) if length else b""
    if masked:
        payload = bytes(payload[i] ^ mask_key[i % 4] for i in range(len(payload)))
    return fin, opcode, payload


def compute_accept(key: str) -> str:
    digest = hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


# ----------------------------------------------------------------- connection
class WSConnection:
    """Framing + message assembly over a connected (TLS) socket."""

    def __init__(self, sock, send_mask: Optional[bytes] = None):
        self.sock = sock
        self.send_mask = send_mask  # injectable for byte-exact tests
        self._inbuf = b""

    def _recv_exact(self, n: int) -> bytes:
        chunks = []
        need = n
        while need > 0:
            try:
                chunk = self.sock.recv(need)
            except (socket.timeout, TimeoutError):
                raise TimeoutError("websocket recv timeout")
            except OSError as e:
                raise ConnectionClosed(1006, str(e)) from e
            if not chunk:
                raise ConnectionClosed(1006, "peer closed mid-frame")
            chunks.append(chunk)
            need -= len(chunk)
        return b"".join(chunks)

    def send_text(self, obj) -> None:
        payload = json.dumps(obj).encode("utf-8")
        mask = self.send_mask or os.urandom(4)
        self.sock.sendall(build_client_frame(WS_TEXT, payload, mask))

    def send_pong(self, payload: bytes) -> None:
        mask = self.send_mask or os.urandom(4)
        self.sock.sendall(build_client_frame(WS_PONG, payload, mask))

    def recv_message(self, timeout: float) -> tuple:
        """Assemble continuation frames; auto-pong pings.

        -> (opcode, parsed_json_or_bytes). Raises TimeoutError when quiet.
        """
        self.sock.settimeout(timeout)
        buffer = b""
        first_opcode = None
        while True:
            fin, opcode, payload = parse_ws_frame(self._recv_exact)
            if opcode == WS_PING:
                self.send_pong(payload)
                continue
            if opcode == WS_PONG:
                continue
            if opcode == WS_CLOSE:
                code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 1006
                raise ConnectionClosed(code, payload[2:].decode("utf-8", errors="replace"))
            if opcode in (WS_TEXT, WS_BINARY):
                buffer, first_opcode = payload, opcode
            elif opcode == 0x0 and first_opcode is not None:
                buffer += payload
            elif opcode == 0x0:
                continue  # stray continuation with no start - drop it
            if fin and first_opcode is not None:
                if first_opcode == WS_TEXT:
                    return WS_TEXT, json.loads(buffer.decode("utf-8"))
                return WS_BINARY, buffer


def ws_handshake(url: str, sock, key: str) -> None:
    """Send the upgrade request and verify the 101 + accept header."""
    host, port, path = _split_ws_url(url)
    key = key or base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"User-Agent: {config.USER_AGENT}\r\n\r\n"
    )
    sock.sendall(request.encode("ascii"))
    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionClosed(1006, "handshake: peer closed")
        raw += chunk
        if len(raw) > 65536:
            raise ConnectionClosed(1002, "handshake response too large")
    header_blob, _, rest = raw.partition(b"\r\n\r\n")
    lines = header_blob.decode("latin-1").split("\r\n")
    if " 101 " not in lines[0]:
        raise ConnectionClosed(1002, f"handshake refused: {lines[0]}")
    accept = ""
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "sec-websocket-accept":
            accept = value.strip()
    if accept != compute_accept(key):
        raise ConnectionClosed(1002, "bad Sec-WebSocket-Accept")
    if rest:
        # frame bytes may have arrived with the handshake - the caller's
        # socket wrapper drains them before touching the network
        sock.pre = rest


def _split_ws_url(url: str) -> tuple:
    rest = url
    tls = True
    if rest.startswith("wss://"):
        rest = rest[6:]
    elif rest.startswith("ws://"):
        rest, tls = rest[5:], False
    host_port, _, path = rest.partition("/")
    host, _, port_s = host_port.partition(":")
    return host, int(port_s or (443 if tls else 80)), "/" + path


def ssl_connect(url: str) -> WSConnection:
    """TLS connect + RFC 6455 handshake -> framed connection. Real path."""
    host, port, path = _split_ws_url(url)
    raw = socket.create_connection((host, port), timeout=15)
    ctx = ssl.create_default_context()
    sock = ctx.wrap_socket(raw, server_hostname=host)

    class _Sock:
        """Channels sendall/recv/settimeout to the ssl socket and preserves
        any application bytes that arrived bundled with the handshake 101."""

        def __init__(self):
            self.pre = b""

        def sendall(self, data):
            sock.sendall(data)

        def recv(self, n):
            if self.pre:
                out, self.pre = self.pre[:n], self.pre[n:]
                return out
            return sock.recv(n)

        def settimeout(self, t):
            sock.settimeout(t)

    ws_sock = _Sock()
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    ws_handshake(url, ws_sock, key)
    return WSConnection(ws_sock)


# ------------------------------------------------------------------------ REST
def bot_headers(token: str) -> dict:
    return {"Authorization": f"Bot {token}"}


def get_gateway_bot(token: str, transport=None) -> dict:
    r = http_get(f"{API_BASE}/gateway/bot", headers=bot_headers(token),
                 transport=transport)
    if r.status == 401:
        raise FatalAuthError("invalid bot token (HTTP 401)")
    if r.status != 200:
        raise TransportError(f"gateway/bot HTTP {r.status}")
    return r.json()


def get_application_id(token: str, transport=None) -> str:
    r = http_get(f"{API_BASE}/applications/@me", headers=bot_headers(token),
                 transport=transport)
    if r.status != 200:
        raise TransportError(f"applications/@me HTTP {r.status}")
    return str(r.json()["id"])


def register_commands(token: str, app_id: str, commands=None,
                      transport=None) -> list:
    """Bulk-replace global slash commands (PUT)."""
    cmds = list(commands if commands is not None else config.SLASH_COMMANDS)
    r = http_put_json(f"{API_BASE}/applications/{app_id}/commands", cmds,
                      headers=bot_headers(token), transport=transport)
    if r.status not in (200, 201):
        raise TransportError(f"register commands HTTP {r.status}: "
                             f"{r.body[:200].decode('utf-8', errors='replace')}")
    return r.json()


def respond_interaction(interaction_id: str, interaction_token: str,
                        data: dict, transport=None):
    """Reply to a slash interaction (type 4: CHANNEL_MESSAGE_WITH_SOURCE)."""
    url = f"{API_BASE}/interactions/{interaction_id}/{interaction_token}/callback"
    r = http_post_json(url, {"type": 4, "data": data}, transport=transport)
    if r.status not in (200, 204):
        raise TransportError(f"interaction callback HTTP {r.status}")


class GatewayClient:
    """Discord gateway session: identify/resume, heartbeats, backoff.

    on_interaction(dispatch_data) is called for every INTERACTION_CREATE;
    the callback is responsible for REST-responding (see commands.respond).
    """

    BACKOFF = (1, 2, 5, 10, 30, 60)

    def __init__(self, token: str, intents: int = 0,
                 on_interaction: Optional[Callable] = None,
                 socket_factory: Optional[Callable] = None,
                 sleep: Callable[[float], None] = time.sleep,
                 now: Callable[[], float] = time.time,
                 log: Callable[[str], None] = print,
                 transport: Optional[Callable] = None,
                 max_iterations: Optional[int] = None):
        self.token = token
        self.intents = intents
        self.on_interaction = on_interaction
        self.socket_factory = socket_factory or ssl_connect
        self.sleep = sleep
        self.now = now
        self.log = log
        self.transport = transport  # injectable REST transport for /gateway/bot
        self.max_iterations = max_iterations  # tests: bound the reconnect loop
        self.session_id: Optional[str] = None
        self.seq: Optional[int] = None
        self._pending_acks = 0

    # ------------------------------------------------------------------ run
    def run(self) -> None:
        attempt = 0
        iterations = 0
        while True:
            try:
                self._session()
                return  # clean exit (session ended without error)
            except FatalAuthError:
                raise
            except SystemExit:
                raise
            except ConnectionClosed as e:
                if e.code == 4004:
                    raise FatalAuthError(
                        "discord closed the session with 4004 - invalid bot token") from e
                attempt += 1
                delay = self.BACKOFF[min(attempt - 1, len(self.BACKOFF) - 1)]
                self.log(f"gateway: {e} - reconnecting in {delay}s")
                self.sleep(delay)
            except (TransportError, TimeoutError, OSError) as e:
                attempt += 1
                delay = self.BACKOFF[min(attempt - 1, len(self.BACKOFF) - 1)]
                self.log(f"gateway: {e} - reconnecting in {delay}s")
                self.sleep(delay)
            except ReconnectNeeded:
                attempt += 1
                delay = self.BACKOFF[min(attempt - 1, len(self.BACKOFF) - 1)]
                self.log(f"gateway: server asked to reconnect - {delay}s")
                self.sleep(delay)
            attempt = max(0, attempt)  # keep backoff growing across failures
            iterations += 1
            if self.max_iterations is not None and iterations >= self.max_iterations:
                return

    def _session(self) -> None:
        gw = get_gateway_bot(self.token, transport=self.transport)
        ws = self.socket_factory(gw.get("url", "wss://gateway.discord.gg"))
        self.log("gateway: connected")
        try:
            opcode, hello = ws.recv_message(timeout=30)
            if opcode != OP_HELLO and hello.get("op") != OP_HELLO:
                raise ConnectionClosed(1002, "expected HELLO op 10")
            interval = float(hello["d"]["heartbeat_interval"]) / 1000.0

            if self.session_id and self.seq is not None:
                self.log("gateway: resuming session")
                ws.send_text({"op": OP_RESUME, "d": {
                    "token": self.token, "session_id": self.session_id,
                    "seq": self.seq}})
            else:
                self.log("gateway: identifying (intents=0, slash only)")
                ws.send_text({"op": OP_IDENTIFY, "d": {
                    "token": self.token, "intents": self.intents,
                    "properties": {"os": "linux", "browser": config.TOOL,
                                   "device": config.TOOL},
                    "compress": False}})

            self._pending_acks = 0
            while True:
                try:
                    opcode, msg = ws.recv_message(timeout=interval)
                except TimeoutError:
                    self._pending_acks += 1
                    if self._pending_acks > 1:
                        raise ReconnectNeeded("heartbeat acks missing")
                    ws.send_text({"op": OP_HEARTBEAT, "d": self.seq})
                    continue
                op = msg.get("op", opcode)
                if op == OP_DISPATCH:
                    self.seq = msg.get("s")
                    t = msg.get("t")
                    if t == "READY":
                        self.session_id = msg["d"]["session_id"]
                        self._pending_acks = 0
                        self.log("gateway: READY")
                    elif t == "RESUMED":
                        self._pending_acks = 0
                        self.log("gateway: RESUMED")
                    elif t == "INTERACTION_CREATE" and self.on_interaction:
                        try:
                            self.on_interaction(msg["d"])
                        except Exception as e:  # noqa: BLE001 - bot must survive
                            self.log(f"interaction handler error: {e}")
                elif op == OP_HEARTBEAT:
                    ws.send_text({"op": OP_HEARTBEAT, "d": self.seq})
                elif op == OP_HEARTBEAT_ACK:
                    self._pending_acks = 0
                elif op == OP_RECONNECT:
                    raise ReconnectNeeded("op 7")
                elif op == OP_INVALID_SESSION:
                    if not msg.get("d"):
                        self.session_id, self.seq = None, None
                    raise ReconnectNeeded("op 9 invalid session")
        finally:
            try:
                self.sock_close(ws)
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def sock_close(ws) -> None:
        sock = getattr(ws, "sock", None)
        if sock is not None:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass
