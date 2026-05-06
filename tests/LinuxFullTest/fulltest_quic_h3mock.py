"""
Mock TCP HTTP server for QUIC h3_upstream fallback testing.

In trojan-plus, QuicProxySession::forward_to_h3_upstream() now:
1. Uses nghttp3 to decode HTTP/3 frames from QUIC streams
2. Converts h3 to HTTP/1.1 format
3. Forwards via TCP to this mock server

The mock server receives an HTTP/1.1 request and responds with a fixed marker.
"""

import sys
import os
import socket
import traceback

print("QUIC h3_upstream mock server early start check", flush=True)

try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.append(current_dir)

    from fulltest_utils import print_time_log

    def main():
        if len(sys.argv) < 2:
            print(f"Usage: {sys.argv[0]} <port>", flush=True)
            sys.exit(1)

        port = int(sys.argv[1])
        print_time_log(f"h3_upstream TCP mock server starting on port {port}")

        try:
            # Use SOCK_STREAM for TCP
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('127.0.0.1', port))
                s.listen(1)
                print_time_log(f"h3_upstream TCP mock server listening on 127.0.0.1:{port}")

                conn, addr = s.accept()
                print_time_log(f"h3_upstream TCP mock server accepted connection from {addr}")

                # Receive HTTP/1.1 request
                request = b""
                while b"\r\n\r\n" not in request:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    request += chunk

                print_time_log(f"h3_upstream TCP mock server received {len(request)} bytes from {addr}")

                # Verify HTTP/1.1 format (request line like "GET /path HTTP/1.1")
                request_text = request.decode('utf-8', errors='replace')
                first_line = request_text.split("\r\n")[0]

                # Check for valid HTTP/1.1 request line
                valid_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
                is_valid = any(first_line.startswith(m + " ") for m in valid_methods)

                if not is_valid:
                    print_time_log(f"h3_upstream TCP mock server: invalid request line: {first_line}")

                # Send HTTP/1.1 response
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: 21\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "H3 Upstream Fallback!"
                )
                conn.sendall(response.encode('utf-8'))
                print_time_log(f"h3_upstream TCP mock server sent response to {addr}")

                conn.close()
                print_time_log(f"h3_upstream TCP mock server closed connection from {addr}")

        except Exception as e:
            print_time_log(f"h3_upstream TCP mock server runtime error: {e}")
            traceback.print_exc()
            sys.exit(1)

    if __name__ == "__main__":
        main()

except Exception as e:
    print(f"h3_upstream TCP mock server fatal boot error: {e}", flush=True)
    traceback.print_exc()
    sys.exit(1)
