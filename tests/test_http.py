import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen

from app import Handler


class HttpTests(unittest.TestCase):
    def test_local_upload_and_recalculation(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            with urlopen(base + "/") as response:
                self.assertIn(b"AD Report Intake", response.read())
            report = "Контроллер домена: Windows Server 2012 R2.".encode()
            request = Request(base + "/analyze", data=report,
                              headers={"X-Filename": "report.txt"}, method="POST")
            with urlopen(request) as response:
                result = json.load(response)
            self.assertEqual(result["observations"]["dc_os"]["value"], 0)
            result["observations"]["dc_access"].update(status="known", value=0.5)
            body = json.dumps({"observations": result["observations"]}).encode()
            request = Request(base + "/evaluate", data=body,
                              headers={"Content-Type": "application/json"}, method="POST")
            with urlopen(request) as response:
                evaluation = json.load(response)
            self.assertEqual(evaluation["vector"]["Контроллеры домена"]["upper"], 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
