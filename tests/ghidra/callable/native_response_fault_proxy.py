#!/usr/bin/env python3
"""Disposable fault injection around real native protocol traffic.

Main response data can be interleaved with synchronous callback queries. Forward
those queries immediately; buffer only the main response bytes until its closing
burst. Fault bytes come from the real Java PackedEncode, not a custom codec.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import traceback

real, mode, config_path, log_path = sys.argv[1:]

def event(phase, **details):
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(json.dumps({"phase": phase, "mode": mode, "native_executable": real,
                              "proxy_pid": os.getpid(), **details}) + "\n")

event("startup", argv=sys.argv)
config = json.loads(Path(config_path).read_text())
opening = base64.b64decode(config["doc_open"])
closing = base64.b64decode(config["doc_close"])
injection = base64.b64decode(config["invalid_support"])
child = subprocess.Popen([real], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr)
event("child_started", pid=child.pid)

def stop(*_):
    child.terminate()
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
    raise SystemExit(86)

signal.signal(signal.SIGTERM, stop)

def input_forward():
    pending = bytearray()
    command_prefix = b"\x00\x00\x01\x02\x00\x00\x01\x0e"
    string_end = b"\x00\x00\x01\x0f"
    try:
        while True:
            data = os.read(0, 65536)
            if not data:
                break
            child.stdin.write(data)
            child.stdin.flush()
            pending.extend(data)
            while True:
                start = pending.find(command_prefix)
                if start < 0:
                    pending[:] = pending[-(len(command_prefix) - 1):]
                    break
                end = pending.find(string_end, start + len(command_prefix))
                if end < 0:
                    del pending[:start]
                    break
                command = bytes(pending[start + len(command_prefix):end]).decode("ascii")
                event("command", command=command)
                del pending[:end + len(string_end)]
    except (BrokenPipeError, OSError):
        pass
    finally:
        child.stdin.close()

threading.Thread(target=input_forward, daemon=True).start()

def tokens():
    pending = None
    while True:
        byte = pending if pending is not None else child.stdout.read(1)
        pending = None
        if not byte:
            return
        if byte == b"\x00":
            marker = bytearray(byte)
            byte = child.stdout.read(1)
            while byte == b"\x00":
                marker.extend(byte)
                byte = child.stdout.read(1)
            if byte != b"\x01":
                raise ValueError("Invalid native burst prefix: " + bytes(marker).hex() + byte.hex())
            marker.extend(byte)
            code = child.stdout.read(1)
            if not code:
                raise EOFError("Truncated native burst")
            marker.extend(code)
            yield "burst", bytes(marker)
        else:
            payload = bytearray(byte)
            while True:
                byte = child.stdout.read(1)
                if not byte or byte == b"\x00":
                    pending = byte
                    break
                payload.extend(byte)
            yield "data", bytes(payload)
            if not byte:
                return

def forward(data):
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()

main_response = None
query_depth = 0
exception_depth = 0
documents = 0
try:
    for kind, token in tokens():
        if kind == "data":
            if main_response is not None and query_depth == 0 and exception_depth == 0:
                main_response.extend(token)
            else:
                forward(token)
            continue
        code = token[-1]
        event("frame", code=code, query_depth=query_depth, main_bytes=None if main_response is None else len(main_response))
        if code == 4:
            query_depth += 1
        elif code == 5:
            query_depth -= 1
        elif code == 10:
            exception_depth += 1
        elif code == 11:
            exception_depth -= 1
        elif code == 14 and query_depth == 0 and exception_depth == 0:
            if main_response is not None:
                raise ValueError("Nested main native response")
            main_response = bytearray()
        elif code == 15 and query_depth == 0 and exception_depth == 0:
            if main_response is None:
                raise ValueError("Main response close without open")
            payload = bytes(main_response)
            main_response = None
            if payload.startswith(opening) and payload.endswith(closing):
                documents += 1
                fault = mode != "pass" and documents > config.get("fault_after_documents", 0)
                event("fault" if fault else "document", pid=child.pid, document=documents,
                      native_doc_bytes=len(payload),
                      native_doc_sha256=hashlib.sha256(payload).hexdigest())
                if documents == 1 and config.get("hold_ready"):
                    # Retain the genuine complete document while another public consumer edits
                    # its source. No callback or result bytes are fabricated or changed here.
                    Path(config["hold_ready"]).write_text(hashlib.sha256(payload).hexdigest())
                    deadline = time.monotonic() + 30
                    while not Path(config["hold_release"]).exists():
                        if time.monotonic() >= deadline:
                            raise TimeoutError("Native document delivery barrier was not released")
                        time.sleep(0.01)
                    event("released_unchanged", pid=child.pid,
                          native_doc_sha256=hashlib.sha256(payload).hexdigest())
                if fault and mode == "crash":
                    stop()
                if mode not in ("malformed", "pass"):
                    if mode != "crash":
                        raise ValueError("Unknown fault mode")
                if fault and mode == "malformed":
                    payload = payload[:-len(closing)] + injection + closing
            forward(payload)
        elif code in (7, 16) and main_response is not None:
            # Preserve native abort/message behavior, without claiming an actual document.
            forward(main_response)
            main_response = None
        forward(token)
except BaseException:
    event("exit", traceback=traceback.format_exc())
    raise
finally:
    if child.poll() is None:
        child.terminate()
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()
