#!/usr/bin/env python3
"""
DES two-device communication over TCP/UDP/HTTP using DES-CBC with random IV per message.

Usage examples (run in separate terminals):

# 1) TCP chat (server auto-replies once)
python des_comm_net.py --mode server --proto tcp --port 5000 --key secretky --auto-reply "Halo juga dari server"
python des_comm_net.py --mode client --proto tcp --host 127.0.0.1 --port 5000 --key secretky --message "Halo dari client"

# 2) UDP
python des_comm_net.py --mode server --proto udp --port 5001 --key secretky --auto-reply "UDP reply ok"
python des_comm_net.py --mode client --proto udp --host 127.0.0.1 --port 5001 --key secretky --message "Halo UDP"

# 3) HTTP (POST /send)
python des_comm_net.py --mode server --proto http --port 8000 --key secretky --auto-reply "HTTP reply ok"
python des_comm_net.py --mode client --proto http --host 127.0.0.1 --port 8000 --key secretky --message "Halo HTTP"

Notes:
- Both devices share the same pre-shared key (DES expects 8 ASCII chars; example: "secretky").
- Messages are sent as base64(IV|ciphertext). Server prints decrypted content and, if --auto-reply is set, sends back one encrypted reply.
- For real bidirectional interactive chat, you can loop send/receive; here we provide a simple request/response demo to keep it minimal.
"""

import os
import sys
import base64
import argparse
import socket
import struct
from typing import Tuple

# Import block-level DES primitives from your existing tugas2.py
# Make sure tugas2.py is in the same directory.
from tugas2 import (
    bytes_to_bits, bits_to_bytes,
    pad_text, unpad_text,
    des_encrypt_block, des_decrypt_block,
    generate_subkeys,
)

BLOCK_SIZE = 8  # bytes for DES


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def des_cbc_encrypt(plaintext: bytes, key: str) -> bytes:
    """Encrypt bytes with DES-CBC. Returns bytes: IV || ciphertext."""
    if not isinstance(key, str):
        key = key.decode("utf-8")
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 characters")

    subkeys = generate_subkeys(key)
    iv = os.urandom(BLOCK_SIZE)

    pt = pad_text(plaintext)
    prev = iv
    out = bytearray()

    for i in range(0, len(pt), BLOCK_SIZE):
        block = pt[i:i+BLOCK_SIZE]
        x = _xor_bytes(block, prev)
        bits = bytes_to_bits(x)
        enc_bits = des_encrypt_block(bits, subkeys)
        ct_block = bits_to_bytes(enc_bits)
        out.extend(ct_block)
        prev = ct_block

    return iv + bytes(out)


def des_cbc_decrypt(iv_ct: bytes, key: str) -> bytes:
    """Decrypt bytes formatted as IV || ciphertext. Returns plaintext bytes (unpadded)."""
    if len(iv_ct) < BLOCK_SIZE:
        raise ValueError("ciphertext too short")
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 characters")

    iv, ct = iv_ct[:BLOCK_SIZE], iv_ct[BLOCK_SIZE:]
    subkeys = generate_subkeys(key)
    prev = iv
    out = bytearray()

    for i in range(0, len(ct), BLOCK_SIZE):
        ct_block = ct[i:i+BLOCK_SIZE]
        bits = bytes_to_bits(ct_block)
        dec_bits = des_decrypt_block(bits, subkeys)
        dec = bits_to_bytes(dec_bits)
        pt_block = _xor_bytes(dec, prev)
        out.extend(pt_block)
        prev = ct_block

    return unpad_text(bytes(out))


# ---------------- TCP helpers ----------------

def _send_framed(conn: socket.socket, data: bytes) -> None:
    """Send length-prefixed frame: 4-byte big-endian length + data."""
    conn.sendall(struct.pack('!I', len(data)) + data)


def _recv_framed(conn: socket.socket) -> bytes:
    """Receive a length-prefixed frame."""
    hdr = _recvn(conn, 4)
    if not hdr:
        return b''
    (length,) = struct.unpack('!I', hdr)
    return _recvn(conn, length)


def _recvn(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


# ---------------- UDP helpers ----------------

def udp_send(sock: socket.socket, addr: Tuple[str, int], payload: bytes) -> None:
    sock.sendto(payload, addr)


def udp_recv(sock: socket.socket, bufsize: int = 65535) -> Tuple[bytes, Tuple[str, int]]:
    data, addr = sock.recvfrom(bufsize)
    return data, addr


# ---------------- HTTP server/client (stdlib only) ----------------
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import http.client

class HTTPHandler(BaseHTTPRequestHandler):
    server_key: str = "secretky"          # injected
    server_auto_reply: str | None = None   # injected

    def do_POST(self):  # handle POST /send
        parsed = urlparse(self.path)
        if parsed.path != '/send':
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length)
        try:
            iv_ct = base64.b64decode(body)
            msg = des_cbc_decrypt(iv_ct, self.server_key).decode('utf-8')
            print(f"[HTTP SERVER] RECV: {msg!r}")
        except Exception as e:
            print(f"[HTTP SERVER] decrypt error: {e}")
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"bad request")
            return

        # Prepare reply (optional)
        reply_plain = self.server_auto_reply or ""
        if reply_plain:
            cipher = des_cbc_encrypt(reply_plain.encode('utf-8'), self.server_key)
            token = base64.b64encode(cipher)
        else:
            token = b""

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(token)

    def log_message(self, fmt, *args):
        # Silence default logging
        return


# ---------------- Main roles ----------------

def run_tcp_server(host: str, port: int, key: str, auto_reply: str | None):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        print(f"[TCP SERVER] listening on {host}:{port}")
        conn, addr = s.accept()
        with conn:
            print(f"[TCP SERVER] connected by {addr}")
            frame = _recv_framed(conn)
            if not frame:
                print("[TCP SERVER] no data")
                return
            try:
                msg = des_cbc_decrypt(frame, key).decode('utf-8')
                print(f"[TCP SERVER] RECV: {msg!r}")
            except Exception as e:
                print(f"[TCP SERVER] decrypt error: {e}")
                return

            if auto_reply:
                cipher = des_cbc_encrypt(auto_reply.encode('utf-8'), key)
                _send_framed(conn, cipher)
                print(f"[TCP SERVER] SENT REPLY: {auto_reply!r}")


def run_tcp_client(host: str, port: int, key: str, message: str):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        cipher = des_cbc_encrypt(message.encode('utf-8'), key)
        _send_framed(s, cipher)
        print(f"[TCP CLIENT] SENT: {message!r}")

        # wait for one reply (optional)
        reply = _recv_framed(s)
        if reply:
            try:
                msg = des_cbc_decrypt(reply, key).decode('utf-8')
                print(f"[TCP CLIENT] RECV REPLY: {msg!r}")
            except Exception as e:
                print(f"[TCP CLIENT] decrypt reply error: {e}")


def run_udp_server(host: str, port: int, key: str, auto_reply: str | None):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((host, port))
        print(f"[UDP SERVER] listening on {host}:{port}")
        data, addr = udp_recv(s)
        try:
            iv_ct = base64.b64decode(data)
            msg = des_cbc_decrypt(iv_ct, key).decode('utf-8')
            print(f"[UDP SERVER] RECV from {addr}: {msg!r}")
        except Exception as e:
            print(f"[UDP SERVER] decrypt error: {e}")
            return

        if auto_reply:
            cipher = des_cbc_encrypt(auto_reply.encode('utf-8'), key)
            token = base64.b64encode(cipher)
            udp_send(s, addr, token)
            print(f"[UDP SERVER] SENT REPLY to {addr}: {auto_reply!r}")


def run_udp_client(host: str, port: int, key: str, message: str):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        cipher = des_cbc_encrypt(message.encode('utf-8'), key)
        token = base64.b64encode(cipher)
        udp_send(s, (host, port), token)
        print(f"[UDP CLIENT] SENT to {(host, port)}: {message!r}")
        # wait one reply (best-effort)
        s.settimeout(3.0)
        try:
            data, addr = udp_recv(s)
            reply_iv_ct = base64.b64decode(data)
            msg = des_cbc_decrypt(reply_iv_ct, key).decode('utf-8')
            print(f"[UDP CLIENT] RECV REPLY from {addr}: {msg!r}")
        except socket.timeout:
            print("[UDP CLIENT] no reply (timeout)")
        except Exception as e:
            print(f"[UDP CLIENT] decrypt reply error: {e}")


def run_http_server(host: str, port: int, key: str, auto_reply: str | None):
    HTTPHandler.server_key = key
    HTTPHandler.server_auto_reply = auto_reply
    httpd = HTTPServer((host, port), HTTPHandler)
    print(f"[HTTP SERVER] listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("[HTTP SERVER] shutting down")
        httpd.server_close()


def run_http_client(host: str, port: int, key: str, message: str):
    cipher = des_cbc_encrypt(message.encode('utf-8'), key)
    token_b64 = base64.b64encode(cipher)

    conn = http.client.HTTPConnection(host, port, timeout=5)
    headers = {"Content-Type": "text/plain"}
    conn.request("POST", "/send", body=token_b64, headers=headers)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()

    print(f"[HTTP CLIENT] SENT: {message!r} -> status {resp.status}")
    if resp.status == 200 and body:
        try:
            reply_iv_ct = base64.b64decode(body)
            msg = des_cbc_decrypt(reply_iv_ct, key).decode('utf-8')
            print(f"[HTTP CLIENT] RECV REPLY: {msg!r}")
        except Exception as e:
            print(f"[HTTP CLIENT] decrypt reply error: {e}")


# ---------------- CLI ----------------

def parse_args():
    p = argparse.ArgumentParser(description="DES two-device comms over TCP/UDP/HTTP (CBC + random IV)")
    p.add_argument('--mode', choices=['server', 'client'], required=True)
    p.add_argument('--proto', choices=['tcp', 'udp', 'http'], required=True)
    p.add_argument('--host', default='127.0.0.1', help='bind/target host (default: 127.0.0.1)')
    p.add_argument('--port', type=int, required=True, help='bind/target port')
    p.add_argument('--key', required=True, help='8-char DES key (ASCII) shared by both devices')
    p.add_argument('--message', help='message to send (client mode)')
    p.add_argument('--auto-reply', dest='auto_reply', help='optional one-shot reply (server mode)')
    return p.parse_args()


def main():
    a = parse_args()
    if len(a.key) != 8:
        print("[ERR] --key must be exactly 8 characters for DES")
        sys.exit(1)

    if a.mode == 'server':
        if a.proto == 'tcp':
            run_tcp_server(a.host, a.port, a.key, a.auto_reply)
        elif a.proto == 'udp':
            run_udp_server(a.host, a.port, a.key, a.auto_reply)
        elif a.proto == 'http':
            run_http_server(a.host, a.port, a.key, a.auto_reply)
    else:  # client
        if not a.message:
            print("[ERR] client mode requires --message")
            sys.exit(1)
        if a.proto == 'tcp':
            run_tcp_client(a.host, a.port, a.key, a.message)
        elif a.proto == 'udp':
            run_udp_client(a.host, a.port, a.key, a.message)
        elif a.proto == 'http':
            run_http_client(a.host, a.port, a.key, a.message)


if __name__ == '__main__':
    main()