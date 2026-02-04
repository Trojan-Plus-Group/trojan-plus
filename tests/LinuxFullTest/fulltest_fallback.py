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
from fulltest_utils import print_time_log, is_windows_system

TEST_HTTP_SERVER_PORT = 18181
TROJAN_SERVER_PORT = 14650
BINARY_PATH = "../../build/trojan"

class MockHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print_time_log(f"Mock HTTP server received GET request for {self.path}")
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Fallback Success")

def wait_for_port(port, timeout=10):
    start_time = time.time()
    while time.time() - start_time < timeout:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('127.0.0.1', port)) == 0:
                return True
        time.sleep(0.5)
    return False

def start_trojan_server(bin_path):
    config_path = os.path.join("config", "fallback_server_config.json")
    print_time_log(f"Starting Trojan server with {config_path}")
    output_log_file = open(os.path.join("config", "fallback_server.output"), "w+")
    
    # On Windows, we should not use restore_signals and avoid redundant executable=
    kwargs = {'universal_newlines': True}
    if not is_windows_system():
        kwargs['restore_signals'] = True

    process = Popen([bin_path, "-c", config_path], 
                    stdout=output_log_file, 
                    stderr=output_log_file,
                    **kwargs)
    return process, output_log_file

def start_mock_http_server():
    print_time_log(f"Starting Mock HTTP server on 127.0.0.1:{TEST_HTTP_SERVER_PORT}")
    output_log_file = open(os.path.join("config", "fallback_mock_server.output"), "w+")
    
    # Use -u for unbuffered output to ensure logs are written to file immediately
    process = Popen([sys.executable, "-u", "fulltest_fallback_mock.py", str(TEST_HTTP_SERVER_PORT)], 
                    stdout=output_log_file, 
                    stderr=output_log_file,
                    universal_newlines=True)
    return process, output_log_file

def main(bin_path=None):
    if bin_path:
        global BINARY_PATH
        BINARY_PATH = bin_path
    
    # Ensure we are in the right directory relative to the script
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # 1. Start Mock HTTP Server
    # Check if port is already in use
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(('127.0.0.1', TEST_HTTP_SERVER_PORT)) == 0:
            print_time_log(f"!!!!! FALLBACK TEST FAILED: Port {TEST_HTTP_SERVER_PORT} is already in use !!!!!")
            if not is_windows_system():
                os.system(f"lsof -i:{TEST_HTTP_SERVER_PORT}")
            return 1

    mock_process, mock_log = start_mock_http_server()
    
    if not wait_for_port(TEST_HTTP_SERVER_PORT):
        print_time_log(f"!!!!! FALLBACK TEST FAILED: Mock HTTP server failed to start on {TEST_HTTP_SERVER_PORT} !!!!!")
        mock_process.terminate()
        mock_log.close()
        # Read and print mock server logs
        output_log_path = os.path.join("config", "fallback_mock_server.output")
        if os.path.exists(output_log_path):
            with open(output_log_path, "r") as f:
                print("--- Mock Server Logs ---")
                print(f.read())
                print("------------------------")
        
        # Environmental Diagnosis
        print_time_log(f"Current Directory: {os.getcwd()}")
        print_time_log(f"Python Search Path: {sys.path}")
        print_time_log(f"Directory Contents: {os.listdir('.')}")
        if not is_windows_system():
            print_time_log("Interface info:")
            os.system("ifconfig -a || ip addr")
        return 1
    
    # 2. Start Trojan Server
    trojan_process, trojan_log = start_trojan_server(BINARY_PATH)
    if not wait_for_port(TROJAN_SERVER_PORT):
        print_time_log(f"!!!!! FALLBACK TEST FAILED: Trojan server failed to start on {TROJAN_SERVER_PORT} !!!!!")
        trojan_process.terminate()
        trojan_log.close()
        mock_process.terminate()
        mock_log.close()
        output_log_path = os.path.join("config", "fallback_server.output")
        if os.path.exists(output_log_path):
            with open(output_log_path, "r") as f:
                print("--- Trojan Server Logs ---")
                print(f.read())
                print("--------------------------")
        return 1
    
    try:
        # 3. Send direct HTTPS request to Trojan Server
        print_time_log(f"Sending HTTPS request to Trojan Server at 127.0.0.1:{TROJAN_SERVER_PORT}")
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        url = f"https://127.0.0.1:{TROJAN_SERVER_PORT}/test_fallback"
        try:
            with urllib.request.urlopen(url, context=ctx, timeout=10) as response:
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
        if 'trojan_process' in locals():
            trojan_process.terminate()
            trojan_process.wait()
        if 'trojan_log' in locals():
            trojan_log.close()
        if 'mock_process' in locals():
            mock_process.terminate()
            mock_process.wait()
        if 'mock_log' in locals():
            mock_log.close()
        
        # Always print logs on failure
        # (Existing log printing logic is already there or handled by caller)



if __name__ == "__main__":
    if len(sys.argv) > 1:
        BINARY_PATH = os.path.abspath(sys.argv[1])
    else:
        BINARY_PATH = os.path.abspath(BINARY_PATH)
    
    # Ensure we are in the right directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    sys.exit(main())
