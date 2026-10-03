"""Minimal Ollama client (standard library only)."""
import json
import urllib.error
import urllib.request


class OllamaError(RuntimeError):
    pass


class Ollama:
    def __init__(self, base_url, model=None, timeout=600):
        self.base = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def with_model(self, model):
        return Ollama(self.base, model or self.model, self.timeout)

    def _open(self, path, body=None):
        req = urllib.request.Request(self.base + path, data=None if body is None else json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="GET" if body is None else "POST")
        try:
            return urllib.request.urlopen(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            detail = e.read()[:300].decode(errors="replace")
            try:
                detail = json.loads(detail).get("error", detail)
            except ValueError:
                pass
            raise OllamaError(f"Ollama returned HTTP {e.code}: {detail}")
        except urllib.error.URLError as e:
            raise OllamaError(f"Could not reach Ollama at {self.base}: {e.reason}")
        except OSError as e:
            raise OllamaError(f"Ollama did not answer in time: {e}")

    def _body(self, messages, stream, num_ctx, temperature, json_mode=False):
        if not self.model:
            raise OllamaError("No model selected. Choose one in Settings.")
        b = {"model": self.model, "stream": stream, "messages": messages,
             "options": {"temperature": temperature, "num_ctx": num_ctx}}
        if json_mode:
            b["format"] = "json"
        return b

    def models(self):
        with self._open("/api/tags") as r:
            return [m["name"] for m in json.loads(r.read()).get("models", [])]

    def chat(self, messages, *, json_mode=False, num_ctx=8192, temperature=0.2):
        with self._open("/api/chat", self._body(messages, False, num_ctx, temperature, json_mode)) as r:
            data = json.loads(r.read())
        if data.get("error"):
            raise OllamaError(str(data["error"]))
        return (data.get("message") or {}).get("content", "")

    def stream(self, messages, *, num_ctx=8192, temperature=0.2):
        """Yield text fragments as the model produces them. Closing the generator closes the connection."""
        r = self._open("/api/chat", self._body(messages, True, num_ctx, temperature))
        try:
            for line in r:
                line = line.strip()
                if not line:
                    continue
                j = json.loads(line)
                if j.get("error"):
                    raise OllamaError(str(j["error"]))
                piece = (j.get("message") or {}).get("content")
                if piece:
                    yield piece
        finally:
            r.close()
