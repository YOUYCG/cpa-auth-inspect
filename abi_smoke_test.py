"""Smoke-test a CLIProxyAPI C ABI plugin without starting the host server."""

from __future__ import annotations

import argparse
import ctypes
import json
import time
from pathlib import Path


class Buffer(ctypes.Structure):
    _fields_ = [("ptr", ctypes.c_void_p), ("length", ctypes.c_size_t)]


PluginCall = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(Buffer),
)
PluginFree = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_size_t)
PluginShutdown = ctypes.CFUNCTYPE(None)


class HostAPI(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("host_ctx", ctypes.c_void_p),
        ("call", ctypes.c_void_p),
        ("free_buffer", ctypes.c_void_p),
    ]


class PluginAPI(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("call", PluginCall),
        ("free_buffer", PluginFree),
        ("shutdown", PluginShutdown),
    ]


def invoke(api: PluginAPI, method: str, request: object | None = None) -> dict:
    payload = b"" if request is None else json.dumps(request).encode("utf-8")
    request_buffer = None
    request_pointer = None
    if payload:
        request_buffer = (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload)
        request_pointer = ctypes.cast(request_buffer, ctypes.POINTER(ctypes.c_uint8))

    response = Buffer()
    started = time.perf_counter()
    status = api.call(
        method.encode("utf-8"),
        request_pointer,
        len(payload),
        ctypes.byref(response),
    )
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    raw = ctypes.string_at(response.ptr, response.length) if response.ptr else b""
    if response.ptr:
        api.free_buffer(response.ptr, response.length)
    decoded = json.loads(raw) if raw else {}
    return {"method": method, "status": status, "elapsed_ms": elapsed_ms, "response": decoded}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("plugin", type=Path)
    args = parser.parse_args()

    library = ctypes.CDLL(str(args.plugin.resolve()))
    init = library.cliproxy_plugin_init
    init.argtypes = [ctypes.POINTER(HostAPI), ctypes.POINTER(PluginAPI)]
    init.restype = ctypes.c_int

    host = HostAPI(abi_version=1)
    plugin = PluginAPI()
    started = time.perf_counter()
    status = init(ctypes.byref(host), ctypes.byref(plugin))
    print(json.dumps({
        "method": "cliproxy_plugin_init",
        "status": status,
        "abi_version": plugin.abi_version,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
    }))
    if status != 0:
        raise SystemExit(status)

    calls = [
        ("plugin.register", None),
        ("plugin.reconfigure", {"config_yaml": ""}),
        ("management.register", None),
        ("management.handle", {
            "Method": "GET",
            "Path": "/v0/resource/plugins/auth-inspect/open",
            "Headers": {},
            "Query": {},
            "Body": "",
        }),
    ]
    for method, request in calls:
        print(json.dumps(invoke(plugin, method, request), ensure_ascii=False))
    plugin.shutdown()


if __name__ == "__main__":
    main()
