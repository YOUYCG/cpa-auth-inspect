package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct { void* ptr; size_t len; } cliproxy_buffer;
typedef struct { uint32_t abi_version; void* host_ctx; void* call; void* free_buffer; } cliproxy_host_api;
typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);
typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
*/
import "C"

import (
	"encoding/json"
	"net/http"
	"strings"
	"unsafe"

	"github.com/YOUYCG/cpa-auth-inspect/cpasdk/pluginabi"
	"github.com/YOUYCG/cpa-auth-inspect/cpasdk/pluginapi"
)

const (
	pluginName    = "auth-inspect"
	pluginVersion = "0.2.0"
	// Default host-side inspector port (docker-compose maps 18318).
	defaultPort = "18318"
)

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(_ *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var rawRequest []byte
	if request != nil && requestLen > 0 {
		rawRequest = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, err := handleMethod(C.GoString(method), rawRequest)
	if err != nil {
		writeResponse(response, errorEnvelope("plugin_error", err.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodManagementRegister:
		return okEnvelope(managementRegistration())
	case pluginabi.MethodManagementHandle:
		return handleManagement(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

type registrationCapability struct {
	ManagementAPI bool `json:"management_api"`
}

type managementRegistrationResponse struct {
	Routes    []pluginapi.ManagementRoute `json:"routes,omitempty"`
	Resources []pluginapi.ResourceRoute   `json:"resources,omitempty"`
}

func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             pluginName,
			Version:          pluginVersion,
			Author:           "local",
			GitHubRepository: "https://github.com/YOUYCG/cpa-auth-inspect",
			ConfigFields:     []pluginapi.ConfigField{},
		},
		Capabilities: registrationCapability{
			ManagementAPI: true,
		},
	}
}

func managementRegistration() managementRegistrationResponse {
	return managementRegistrationResponse{
		Resources: []pluginapi.ResourceRoute{
			{
				Path:        "/open",
				Menu:        "认证巡检",
				Description: "打开多厂商认证巡检（xAI / Codex / Claude / Gemini）",
			},
		},
	}
}

func handleManagement(raw []byte) ([]byte, error) {
	var req pluginapi.ManagementRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	path := strings.TrimRight(req.Path, "/")
	resourcePrefix := "/v0/resource/plugins/" + pluginName
	if strings.ToUpper(strings.TrimSpace(req.Method)) == http.MethodGet &&
		(strings.HasSuffix(path, resourcePrefix+"/open") || strings.HasSuffix(path, resourcePrefix+"/status")) {
		return okEnvelope(pluginapi.ManagementResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Content-Type": {"text/html; charset=utf-8"}},
			Body:       []byte(openPage()),
		})
	}
	return okEnvelope(pluginapi.ManagementResponse{
		StatusCode: http.StatusNotFound,
		Headers:    http.Header{"Content-Type": {"application/json; charset=utf-8"}},
		Body:       []byte(`{"error":"not_found"}`),
	})
}

func openPage() string {
	// Host is resolved in-browser so LAN access uses the same hostname as CPA.
	return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>认证巡检</title>
  <style>
    html,body{margin:0;height:100%;background:#0f172a;color:#e2e8f0;font-family:Inter,system-ui,sans-serif}
    .bar{display:flex;align-items:center;gap:10px;padding:10px 14px;background:#111827;border-bottom:1px solid #1f2937}
    .bar a,.bar button{color:#fff;text-decoration:none;background:#2563eb;border:0;border-radius:6px;padding:7px 12px;font:inherit;font-weight:600;cursor:pointer}
    .bar a.secondary,.bar button.secondary{background:#334155}
    .bar span{color:#94a3b8;font-size:12px;margin-left:auto}
    iframe{border:0;width:100%;height:calc(100% - 48px);background:#f4f6f8}
    .fallback{padding:28px;max-width:720px;margin:40px auto;line-height:1.6}
    .fallback code{background:#1e293b;padding:2px 6px;border-radius:4px}
  </style>
</head>
<body>
  <div class="bar">
    <strong>认证巡检</strong>
    <a id="openTab" class="secondary" href="#" target="_blank" rel="noopener">新标签打开</a>
    <button class="secondary" onclick="reloadFrame()">刷新</button>
    <span id="hint">正在连接巡检服务…</span>
  </div>
  <iframe id="frame" title="auth-inspect"></iframe>
  <script>
    const port = '` + defaultPort + `';
    const host = location.hostname || '127.0.0.1';
    const proto = location.protocol === 'https:' ? 'https:' : 'http:';
    // Prefer same hostname as management panel; fallback list for local setups.
    const candidates = [
      proto + '//' + host + ':' + port + '/',
      'http://127.0.0.1:' + port + '/',
      'http://localhost:' + port + '/'
    ];
    const frame = document.getElementById('frame');
    const openTab = document.getElementById('openTab');
    const hint = document.getElementById('hint');
    let idx = 0;

    function setUrl(url) {
      frame.src = url;
      openTab.href = url;
      hint.textContent = url;
    }

    async function probe(url) {
      try {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), 2500);
        const res = await fetch(url + 'healthz', { signal: ctrl.signal, mode: 'cors', cache: 'no-store' });
        clearTimeout(t);
        return res.ok;
      } catch (_) {
        // healthz may block CORS; still try iframe load.
        return false;
      }
    }

    async function pick() {
      for (let i = 0; i < candidates.length; i++) {
        const url = candidates[i];
        const ok = await probe(url);
        if (ok) { setUrl(url); hint.textContent = '已连接 · ' + url; return; }
      }
      // Fallback: still point iframe at first candidate; user can use "新标签打开".
      setUrl(candidates[0]);
      hint.textContent = '若空白：请确认 docker 中 xai-inspect 已启动，并点「新标签打开」 · ' + candidates[0];
    }

    function reloadFrame() { frame.src = frame.src; }
    pick();
  </script>
</body>
</html>`
}

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func okEnvelope(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
