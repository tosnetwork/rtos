#!/usr/bin/env python3
"""Keep failing local-node responses reviewable without accepting or retrying them."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import unittest

from mixed_matrix import rpc


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        method = request['method']
        if method == 'success':
            code, body = 200, json.dumps({'result': {'height': 197}}).encode()
        elif method == 'json_error':
            code, body = 200, json.dumps({'error': {'code': 500, 'message': 'proof not ready'}}).encode()
        elif method == 'oversized':
            code, body = 500, b'x' * 70000
        else:
            code, body = 500, json.dumps({'error': {'message': 'cannot load block proof'}}).encode()
        self.send_response(code)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class RpcDiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.start()
        cls.url = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_success(self):
        self.assertEqual(rpc(self.url, 'success'), {'height': 197})

    def test_http_error_preserves_method_height_and_body(self):
        with self.assertRaises(RuntimeError) as caught:
            rpc(self.url, 'getMasterchainBlockSignatures', {'seqno': 197})
        for text in ['getMasterchainBlockSignatures', "'seqno': 197", 'HTTP 500', 'cannot load block proof']:
            self.assertIn(text, str(caught.exception))

    def test_json_error_remains_failure(self):
        with self.assertRaisesRegex(RuntimeError, 'json_error.*proof not ready'):
            rpc(self.url, 'json_error')

    def test_oversized_error_is_bounded(self):
        with self.assertRaises(RuntimeError) as caught:
            rpc(self.url, 'oversized')
        self.assertIn('[response truncated]', str(caught.exception))
        self.assertLess(len(str(caught.exception)), 66000)


if __name__ == '__main__':
    unittest.main()
