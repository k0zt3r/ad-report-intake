"""Локальный веб-интерфейс и CLI модуля обработки отчётов об AD."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from core import MAX_UPLOAD_BYTES, analyze, evaluate

INDEX = Path(__file__).with_name("index.html")


class Handler(BaseHTTPRequestHandler):
    def _reply(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != "/":
            self._reply(404, b"Not found", "text/plain; charset=utf-8")
            return
        self._reply(200, INDEX.read_bytes(), "text/html; charset=utf-8")

    def do_POST(self) -> None:
        if self.path not in ("/analyze", "/evaluate"):
            self._reply(404, b"Not found", "text/plain; charset=utf-8")
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > MAX_UPLOAD_BYTES:
                raise ValueError("Допустимый размер запроса: от 1 байта до 10 МБ")
            payload = self.rfile.read(size)
            if self.path == "/analyze":
                name = unquote(self.headers.get("X-Filename", ""))
                result = analyze(name, payload)
            else:
                result = evaluate(json.loads(payload)["observations"])
            self._reply(200, json.dumps(result, ensure_ascii=False).encode("utf-8"),
                        "application/json; charset=utf-8")
        except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
            self._reply(400, json.dumps({"error": str(exc)}, ensure_ascii=False).encode("utf-8"),
                        "application/json; charset=utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Извлечь факты AD из отчёта")
    parser.add_argument("--input", type=Path, help="TXT, MD, DOCX или текстовый PDF")
    parser.add_argument("--out", type=Path, help="Сохранить результат в JSON")
    parser.add_argument("--serve", action="store_true", help="Открыть локальный веб-интерфейс")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if args.serve:
        with ThreadingHTTPServer(("127.0.0.1", args.port), Handler) as server:
            print(f"Откройте http://127.0.0.1:{args.port}/")
            server.serve_forever()
    elif args.input:
        result = analyze(args.input.name, args.input.read_bytes())
        output = json.dumps(result, ensure_ascii=False, indent=2)
        if args.out:
            args.out.write_text(output + "\n", encoding="utf-8")
            print(args.out)
        else:
            print(output)
    else:
        parser.error("Укажите --serve или --input")


if __name__ == "__main__":
    main()
