"""Minimal OpenAI-compatible chat completions server. Lets opencode run a full
agent step with no real model/token.

Usage: fake_openai.py [port] [shell command]. Every reply is a short text,
except with a shell command: a request that offers tools and has no tool
result yet then gets a `shell` tool call running that command."""

import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("fake-openai: " + (fmt % args) + "\n")

    def do_GET(self):
        body = json.dumps({"object": "list", "data": [{"id": "fake", "object": "model"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        sys.stderr.write(f"fake-openai: POST {self.path} stream={req.get('stream')}\n")
        base = {
            "id": "c1",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": "fake",
        }
        if (
            self.server.shell_command
            and req.get("tools")
            and not any(m.get("role") == "tool" for m in req.get("messages", []))
        ):
            call = {
                "index": 0,
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": "shell",
                    "arguments": json.dumps(
                        {"command": self.server.shell_command, "description": "coi test"}
                    ),
                },
            }
            self._stream(
                base,
                {"role": "assistant", "tool_calls": [call]},
                "tool_calls",
            )
            return
        if not req.get("stream"):
            body = json.dumps(
                {
                    **base,
                    "object": "chat.completion",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "ok"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._stream(base, {"role": "assistant", "content": "ok"}, "stop")

    def _stream(self, base, delta, finish_reason):
        """Stream one delta, then the finish chunk and [DONE]."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        chunks = [
            {**base, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
            {
                **base,
                "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            },
        ]
        for c in chunks:
            self.wfile.write(f"data: {json.dumps(c)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1]) if len(sys.argv) > 1 else 18080), H)
    server.shell_command = sys.argv[2] if len(sys.argv) > 2 else None
    server.serve_forever()
