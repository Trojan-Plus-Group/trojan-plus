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

def wait_for_port(port, host="127.0.0.1", timeout=10):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    addr = (host, port, 0, 0) if family == socket.AF_INET6 else (host, port)
    start_time = time.time()
    while time.time() - start_time < timeout:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                if s.connect_ex(addr) == 0:
                    return True
            except OSError:
                pass
        time.sleep(0.5)
    return False

def start_trojan_server(bin_path, server_config="fallback_server_config.json"):
    config_path = os.path.join("config", server_config)
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

def start_mock_http_server(mock_bind="0.0.0.0"):
    print_time_log(f"Starting Mock HTTP server on {mock_bind}:{TEST_HTTP_SERVER_PORT}")
    output_log_file = open(os.path.join("config", "fallback_mock_server.output"), "w+")
    
    # Use -u for unbuffered output to ensure logs are written to file immediately
    process = Popen([sys.executable, "-u", "fulltest_fallback_mock.py", str(TEST_HTTP_SERVER_PORT), mock_bind], 
                    stdout=output_log_file, 
                    stderr=output_log_file,
                    universal_newlines=True)
    return process, output_log_file

def main(bin_path=None, mock_bind="0.0.0.0", request_host="127.0.0.1", server_config="fallback_server_config.json"):
    if bin_path:
        global BINARY_PATH
        BINARY_PATH = bin_path
    
    # Ensure we are in the right directory relative to the script
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # 1. Start Mock HTTP Server
    # Check if port is already in use. Default remains an IPv4 check against 127.0.0.1.
    mock_check_host = "127.0.0.1" if mock_bind in ("0.0.0.0", "") else mock_bind
    mock_family = socket.AF_INET6 if ":" in mock_check_host else socket.AF_INET
    mock_addr = (mock_check_host, TEST_HTTP_SERVER_PORT, 0, 0) if mock_family == socket.AF_INET6 else (mock_check_host, TEST_HTTP_SERVER_PORT)
    with socket.socket(mock_family, socket.SOCK_STREAM) as s:
        try:
            port_busy = s.connect_ex(mock_addr) == 0
        except OSError:
            port_busy = False
        if port_busy:
            print_time_log(f"!!!!! FALLBACK TEST FAILED: Port {TEST_HTTP_SERVER_PORT} is already in use !!!!!")
            if not is_windows_system():
                os.system(f"lsof -i:{TEST_HTTP_SERVER_PORT}")
            return 1

    mock_process, mock_log = start_mock_http_server(mock_bind)
    
    if not wait_for_port(TEST_HTTP_SERVER_PORT, mock_check_host):
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
    trojan_process, trojan_log = start_trojan_server(BINARY_PATH, server_config)
    if not wait_for_port(TROJAN_SERVER_PORT, request_host):
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
        print_time_log(f"Sending HTTPS request to Trojan Server at {request_host}:{TROJAN_SERVER_PORT}")
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        host_for_url = f"[{request_host}]" if ":" in request_host else request_host
        url = f"https://{host_for_url}:{TROJAN_SERVER_PORT}/test_fallback"
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
