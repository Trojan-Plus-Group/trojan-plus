import os
import sys
import time
import socket
import threading
import ssl
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from subprocess import Popen

# Add current directory to path so we can import fulltest_utils
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from fulltest_utils import print_time_log

TEST_HTTP_SERVER_PORT = 18081
TROJAN_SERVER_PORT = 14650
BINARY_PATH = "../../build/trojan"

class MockHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print_time_log(f"Mock HTTP server received GET request for {self.path}")
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Fallback Success")

def run_mock_http_server():
    httpd = HTTPServer(('127.0.0.1', TEST_HTTP_SERVER_PORT), MockHTTPHandler)
    print_time_log(f"Mock HTTP server started on {TEST_HTTP_SERVER_PORT}")
    httpd.serve_forever()

def start_trojan_server():
    config_path = "config/fallback_server_config.json"
    print_time_log(f"Starting Trojan server with {config_path}")
    output_log_file = open("config/fallback_server.output", "w+")
    process = Popen([BINARY_PATH, "-c", config_path], 
                    executable=BINARY_PATH,
                    stdout=output_log_file, 
                    stderr=output_log_file,
                    universal_newlines=True)
    return process, output_log_file

def main():
    # 1. Start Mock HTTP Server
    t = threading.Thread(target=run_mock_http_server)
    t.daemon = True
    t.start()
    
    # 2. Start Trojan Server
    trojan_process, log_file = start_trojan_server()
    time.sleep(2) # Wait for Trojan to start
    
    try:
        # 3. Send direct HTTPS request to Trojan Server
        print_time_log(f"Sending HTTPS request to Trojan Server at 127.0.0.1:{TROJAN_SERVER_PORT}")
        
        # We need to ignore SSL cert verification because it's a self-signed cert in tests
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        url = f"https://127.0.0.1:{TROJAN_SERVER_PORT}/test_fallback"
        try:
            with urllib.request.urlopen(url, context=ctx, timeout=5) as response:
                body = response.read().decode('utf-8')
                print_time_log(f"Response body: {body}")
                if body == "Fallback Success":
                    print_time_log("!!!!! FALLBACK TEST SUCCEEDED !!!!!")
                    return 0
                else:
                    print_time_log(f"!!!!! FALLBACK TEST FAILED: Unexpected body {body} !!!!!")
                    return 1
        except Exception as e:
            print_time_log(f"!!!!! FALLBACK TEST FAILED: {str(e)} !!!!!")
            return 1
            
    finally:
        print_time_log("Cleaning up...")
        trojan_process.terminate()
        trojan_process.wait()
        log_file.close()
        # Read and print trojan logs on failure
        with open("config/fallback_server.output", "r") as f:
            print("--- Trojan Server Logs ---")
            print(f.read())
            print("--------------------------")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        BINARY_PATH = os.path.abspath(sys.argv[1])
    else:
        BINARY_PATH = os.path.abspath(BINARY_PATH)
    
    # Ensure we are in the right directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    sys.exit(main())
