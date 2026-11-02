#!/usr/bin/env python3
"""
Veridex AI - Local Test Server
Serves the Veridex AI test lab and simulated scenarios locally for testing.
"""

import http.server
import socketserver
import os
import sys

PORT = 8000
DIRECTORY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def end_headers(self):
        # Enable CORS and caching headers for testing
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        super().end_headers()

def main():
    print("=" * 60)
    print(" Veridex AI - Local Phishing Test Server")
    print("=" * 60)
    print(f" Serving directory: {DIRECTORY}")
    print(f" Test Lab URL:     http://localhost:{PORT}/test-lab/index.html")
    print(f" Banking Phish:    http://localhost:{PORT}/test-lab/scenarios/fake-banking.html")
    print(f" Shopping Scam:    http://localhost:{PORT}/test-lab/scenarios/scam-shopping.html")
    print(f" Crypto Phish:     http://localhost:{PORT}/test-lab/scenarios/fake-crypto.html")
    print(f" Homoglyph Phish:  http://localhost:{PORT}/test-lab/scenarios/idn-homoglyph.html")
    print(f" Neutral Site:     http://localhost:{PORT}/test-lab/scenarios/neutral-sample.html")
    print("-" * 60)
    print(" Press Ctrl+C to stop the server.")
    print("=" * 60)

    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.")

if __name__ == '__main__':
    main()
