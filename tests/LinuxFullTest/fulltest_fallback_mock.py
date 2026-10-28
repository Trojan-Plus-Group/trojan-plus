import sys
import os
import socket
import traceback

# No-dependency print for immediate feedback
print("Mock HTTP server process early start check", flush=True)

try:
    # Force absolute path for imports
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.append(current_dir)
    
    from fulltest_utils import print_time_log
    print("Mock HTTP server imports successful", flush=True)

    def main():
        if len(sys.argv) < 2:
            print(f"Usage: {sys.argv[0]} <port>", flush=True)
            sys.exit(1)
        
        port = int(sys.argv[1])
        bind_host = sys.argv[2] if len(sys.argv) >= 3 else "0.0.0.0"
        family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
        print_time_log(f"Mock HTTP server starting raw socket on {bind_host}:{port}")
        
        try:
            # Create a raw TCP socket to act as a minimal HTTP server
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    # Fallback mock is bound to an IPv6 address. Do not accept
                    # an IPv4-mapped peer on this socket.
                    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                print_time_log(f"Attempting to bind to {bind_host}:{port}")
                s.bind((bind_host, port))
                s.listen(5)
                print_time_log(f"Mock HTTP server listening on {bind_host}:{port}")
                
                while True:
                    conn, addr = s.accept()
                    with conn:
                        print_time_log(f"Mock HTTP server accepted connection from {addr}")
                        data = conn.recv(1024)
                        if not data:
                            continue
                        
                        # Send a minimal valid HTTP response
                        response = (
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/plain\r\n"
                            "Content-Length: 16\r\n"
                            "Connection: close\r\n"
                            "\r\n"
                            "Fallback Success"
                        )
                        conn.sendall(response.encode('utf-8'))
                        print_time_log(f"Mock HTTP server sent response to {addr}")
        except Exception as e:
            print_time_log(f"Mock HTTP server runtime error: {e}")
            traceback.print_exc()
            sys.exit(1)

    if __name__ == "__main__":
        main()

except Exception as e:
    print(f"Mock HTTP server fatal boot error: {e}", flush=True)
    traceback.print_exc()
    sys.exit(1)
