import base64
import json
import struct
import unittest

from leviathan_triage import config
from leviathan_triage.gateway import (API_BASE, ConnectionClosed,
                                      FatalAuthError, GatewayClient,
                                      ReconnectNeeded, WSConnection,
                                      build_client_frame, compute_accept,
                                      get_gateway_bot, parse_ws_frame,
                                      register_commands, respond_interaction,
                                      ws_handshake, _split_ws_url)
from leviathan_triage.http import Response


def recv_from(data: bytes):
    it = iter(data)
    def _recv(n: int) -> bytes:
        out = b""
        for _ in range(n):
            try:
                out += bytes([next(it)])
            except StopIteration:
                break
        return out
    return _recv


class TestFrames(unittest.TestCase):
    def test_masked_roundtrip_small(self):
        mask = b"\x01\x02\x03\x04"
        payload = b'{"op":1,"d":null}'
        raw = build_client_frame(1, payload, mask)
        fin, opcode, got = parse_ws_frame(recv_from(raw))
        self.assertTrue(fin)
        self.assertEqual(opcode, 1)
        self.assertEqual(got, payload)

    def test_extended_length_126(self):
        mask = b"\xaa\xbb\xcc\xdd"
        payload = b"x" * 300
        raw = build_client_frame(WS_TEXT := 0x1, payload, mask)
        fin, opcode, got = parse_ws_frame(recv_from(raw))
        self.assertEqual(got, payload)
        self.assertEqual(len(raw), 2 + 2 + 4 + 300)

    def test_extended_length_127(self):
        mask = b"\x00\x00\x00\x01"
        payload = b"y" * 70000
        raw = build_client_frame(0x1, payload, mask)
        _, opcode, got = parse_ws_frame(recv_from(raw))
        self.assertEqual(opcode, 0x1)
        self.assertEqual(got, payload)

    def test_bad_mask_rejected(self):
        with self.assertRaises(ValueError):
            build_client_frame(1, b"x", b"123")

    def test_accept_rfc_example(self):
        # RFC 6455 section 1.3 worked example
        self.assertEqual(compute_accept("dGhlIHNhbXBsZSBub25jZQ=="),
                         "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")


class FakeStreamSock:
    """Byte-stream socket fed from a string; records sendall."""

    def __init__(self, response: str):
        self.data = response.encode("latin-1")
        self.sent = []

    def sendall(self, b):
        self.sent.append(b)

    def recv(self, n):
        out, self.data = self.data[:n], self.data[n:]
        return out

    def settimeout(self, t):
        pass


class TestHandshake(unittest.TestCase):
    def test_happy_path(self):
        key = base64.b64encode(b"\x00" * 16).decode()
        accept = compute_accept(key)
        resp = (f"HTTP/1.1 101 Switching Protocols\r\n"
                f"Upgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n")
        sock = FakeStreamSock(resp)
        ws_handshake("wss://gateway.discord.gg/?v=10", sock, key)
        req = sock.sent[0].decode()
        self.assertIn("GET /?v=10 HTTP/1.1", req)
        self.assertIn("Host: gateway.discord.gg:443", req)
        self.assertIn("Upgrade: websocket", req)
        self.assertIn("Sec-WebSocket-Version: 13", req)

    def test_wrong_accept_rejected(self):
        resp = ("HTTP/1.1 101 Switching Protocols\r\n"
                "Sec-WebSocket-Accept: wrong\r\n\r\n")
        with self.assertRaises(ConnectionClosed):
            ws_handshake("wss://gateway.discord.gg", FakeStreamSock(resp), "somekey")

    def test_non_101_rejected(self):
        with self.assertRaises(ConnectionClosed):
            ws_handshake("wss://gateway.discord.gg",
                         FakeStreamSock("HTTP/1.1 404 Not Found\r\n\r\n"), "somekey")

    def test_split_url(self):
        self.assertEqual(_split_ws_url("wss://gateway.discord.gg/?v=10"),
                         ("gateway.discord.gg", 443, "/?v=10"))
        self.assertEqual(_split_ws_url("ws://localhost:9000/x"),
                         ("localhost", 9000, "/x"))


class FakeWS:
    """Duck-typed WSConnection with a scripted recv sequence."""

    def __init__(self, incoming, fail_timeouts=0):
        self.incoming = list(incoming)
        self.sent = []
        self.fail_timeouts = fail_timeouts
        self.closed = False
        self.sock = self

    def send_text(self, obj):
        self.sent.append(obj)

    def recv_message(self, timeout):
        if self.fail_timeouts:
            self.fail_timeouts -= 1
            raise TimeoutError("quiet")
        if not self.incoming:
            raise ConnectionClosed(1000, "script exhausted")
        item = self.incoming.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def close(self):
        self.closed = True


def hello(interval=1000):
    return 10, {"op": 10, "d": {"heartbeat_interval": interval, "_trace": ["x"]}}

def dispatch(t, d=None, seq=1):
    return 0, {"op": 0, "t": t, "s": seq, "d": d or {}}

def reconnect():
    return 7, {"op": 7, "d": None}


class TestGatewayClient(unittest.TestCase):
    def _client(self, incoming, **kw):
        ws = FakeWS(incoming)
        logs = []
        rest = kw.pop("rest_transport", None) or (
            lambda url, timeout, headers: Response(200, json.dumps({"url": "wss://fake"}).encode()))
        client = GatewayClient("TOKEN", on_interaction=kw.pop("on_interaction", None),
                               socket_factory=lambda url: ws,
                               sleep=lambda s: logs.append(f"sleep {s}"),
                               log=logs.append,
                               transport=rest,
                               max_iterations=kw.pop("max_iterations", 1), **kw)
        return client, ws, logs

    def test_identify_on_fresh_session(self):
        client, ws, logs = self._client([hello(), dispatch("READY", {"session_id": "s1"}, 1),
                                         reconnect()])
        client.run()
        self.assertEqual(ws.sent[0]["op"], 2)
        self.assertEqual(ws.sent[0]["d"]["intents"], 0)
        self.assertFalse(ws.sent[0]["d"]["compress"])
        self.assertEqual(client.session_id, "s1")

    def test_resume_on_existing_session(self):
        client, ws, logs = self._client([hello(), dispatch("RESUMED", {}, 2),
                                         reconnect()])
        client.session_id = "s-old"
        client.seq = 7
        client.run()
        self.assertEqual(ws.sent[0]["op"], 6)
        self.assertEqual(ws.sent[0]["d"]["session_id"], "s-old")
        self.assertEqual(ws.sent[0]["d"]["seq"], 7)

    def test_heartbeat_after_timeout(self):
        client, ws, logs = self._client([hello(), TimeoutError("quiet"),
                                         reconnect()])
        client.run()
        ops = [s["op"] for s in ws.sent]
        self.assertEqual(ops, [2, 1])  # identify, then heartbeat

    def test_missing_acks_trigger_reconnect(self):
        client, ws, logs = self._client([hello(), TimeoutError("quiet"),
                                         TimeoutError("quiet")])
        client.run()
        ops = [s["op"] for s in ws.sent]           # identify + one heartbeat
        self.assertEqual(ops, [2, 1])
        self.assertTrue(any("reconnect" in str(x) for x in logs))

    def test_interaction_dispatched(self):
        seen = []

        def on_interaction(d):
            seen.append(d)

        interaction = {"id": "1", "token": "tok",
                       "data": {"name": "kev-today", "options": []}}
        client, ws, logs = self._client([hello(),
                                         dispatch("INTERACTION_CREATE", interaction, 5),
                                         reconnect()], on_interaction=on_interaction)
        client.run()
        self.assertEqual(seen, [interaction])

    def test_handler_crash_does_not_kill_session(self):
        def boom(d):
            raise RuntimeError("handler blew up")

        client, ws, logs = self._client([hello(),
                                         dispatch("INTERACTION_CREATE", {"id": "1"}, 5),
                                         reconnect()], on_interaction=boom)
        client.run()  # must not raise
        self.assertTrue(any("blew up" in str(x) for x in logs))

    def test_invalid_session_clears_state(self):
        client, ws, logs = self._client([hello(), (9, {"op": 9, "d": False}),
                                         hello(), reconnect()])
        client.session_id = "s-old"
        client.seq = 3
        client.max_iterations = 2
        client.run()
        self.assertIsNone(client.session_id)     # cleared -> next is identify
        self.assertEqual(ws.sent[-1]["op"], 2)

    def test_close_4004_is_fatal(self):
        client, ws, logs = self._client([hello(), ConnectionClosed(4004, "auth")])
        with self.assertRaises(FatalAuthError):
            client.run()

    def test_backoff_grows(self):
        client, ws, logs = self._client([reconnect(), reconnect()])
        client.max_iterations = 2
        client.run()
        sleeps = [x for x in logs if str(x).startswith("sleep")]
        self.assertEqual(sleeps[0], "sleep 1")
        self.assertEqual(sleeps[1], "sleep 2")


class TestGatewayREST(unittest.TestCase):
    def test_get_gateway_bot(self):
        def transport(url, timeout, headers):  # GET shape
            return Response(200, json.dumps({"url": "wss://gw"}).encode())
        self.assertEqual(get_gateway_bot("T", transport=transport)["url"], "wss://gw")

    def test_bad_token_is_fatal(self):
        def transport(url, timeout, headers):
            return Response(401, b'{"message": "401"}')
        with self.assertRaises(FatalAuthError):
            get_gateway_bot("BAD", transport=transport)

    def test_register_commands_put(self):
        sent = {}

        def transport(url, payload, timeout, headers):
            sent.update(url=url, payload=payload,
                        auth=headers.get("Authorization"))
            return Response(200, json.dumps(config.SLASH_COMMANDS).encode())

        got = register_commands("T", "APP123", transport=transport)
        self.assertEqual(sent["url"], f"{API_BASE}/applications/APP123/commands")
        self.assertEqual(sent["auth"], "Bot T")
        self.assertEqual([c["name"] for c in got],
                         [c["name"] for c in config.SLASH_COMMANDS])

    def test_respond_interaction(self):
        sent = {}

        def transport(url, payload, timeout, headers):
            sent.update(url=url, payload=payload)
            return Response(204, b"")

        respond_interaction("i-1", "itok", {"embeds": [{"title": "x"}]},
                            transport=transport)
        self.assertEqual(sent["url"], f"{API_BASE}/interactions/i-1/itok/callback")
        self.assertEqual(sent["payload"]["type"], 4)


class TestWSConnectionOverRealFrames(unittest.TestCase):
    """Drive WSConnection through actual encoded bytes (integration layer)."""

    def _ws(self, raw_bytes, mask=b"\x00\x00\x00\x00"):
        sent = []

        class S:  # faithful socket: recv(n) returns at most n bytes
            def __init__(self, data):
                self.data = data

            def sendall(self, b):
                sent.append(b)

            def recv(self, n):
                out, self.data = self.data[:n], self.data[n:]
                return out

            def settimeout(self, t):
                pass

        return WSConnection(S(raw_bytes)), sent

    def test_text_message_parsed(self):
        payload = json.dumps({"op": 10, "d": {"heartbeat_interval": 41250}}).encode()
        mask = b"\x01\x02\x03\x04"
        raw = build_client_frame(0x1, payload, mask)  # masking irrelevant for parse
        ws, sent = self._ws(raw)
        opcode, obj = ws.recv_message(timeout=5)
        self.assertEqual(opcode, 0x1)
        self.assertEqual(obj["op"], 10)

    def test_ping_gets_pong(self):
        raw = build_client_frame(0x9, b"pingdata", b"\x00\x00\x00\x00")
        payload = json.dumps({"op": 11}).encode()
        raw += build_client_frame(0x1, payload, b"\x00\x00\x00\x00")
        ws, sent = self._ws(raw)
        opcode, obj = ws.recv_message(timeout=5)
        self.assertEqual(obj["op"], 11)
        # first sent bytes must be a pong carrying the ping payload
        fin, opcode, got = parse_ws_frame(recv_from(sent[0]))
        self.assertEqual(opcode, 0xA)
        self.assertEqual(got, b"pingdata")

    def test_continuation_assembly(self):
        p1 = b'{"op": 0, "t": "READY", "d": {"session_id": "'
        p2 = b'abc123"}}'
        raw = build_client_frame(0x1, p1, b"\x00\x00\x00\x00", fin=False)
        raw += build_client_frame(0x0, p2, b"\x00\x00\x00\x00")
        ws, sent = self._ws(raw)
        opcode, obj = ws.recv_message(timeout=5)
        self.assertEqual(obj["d"]["session_id"], "abc123")

    def test_close_frame_raises_with_code(self):
        raw = struct.pack("!BBH", 0x88, 2, 4004) + b"auth"
        ws, _ = self._ws(raw)
        with self.assertRaises(ConnectionClosed) as ctx:
            ws.recv_message(timeout=5)
        self.assertEqual(ctx.exception.code, 4004)


if __name__ == "__main__":
    unittest.main()
