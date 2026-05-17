"""
Mock TCP HTTP server for QUIC h3_upstream fallback testing.

In trojan-plus, QuicProxySession::forward_to_h1_upstream() now:
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
                s.listen(8)
                print_time_log(f"h3_upstream TCP mock server listening on 127.0.0.1:{port}")

                # Loop accepting connections so that spurious probes (e.g. SOCKS5
                # port-readiness checks that reach the trojan client and trigger
                # an empty upstream session) do not consume the single accept slot
                # before the real request arrives.
                import threading

                def handle_client(conn, addr):
                    conn.settimeout(2.0)
                    print_time_log(f"h3_upstream TCP mock server accepted connection from {addr}")
                    try:
                        request = b""
                        try:
                            while b"\r\n\r\n" not in request:
                                chunk = conn.recv(4096)
                                if not chunk:
                                    break
                                request += chunk
                        except (socket.timeout, TimeoutError):
                            pass

                        if b"HTTP/" in request:
                            print_time_log(f"h3_upstream TCP mock server received {len(request)} bytes from {addr}")
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
                    except Exception as e:
                        print_time_log(f"h3_upstream TCP mock server runtime error handling {addr}: {e}")
                    finally:
                        try:
                            conn.close()
                        except Exception:
                            pass
                        print_time_log(f"h3_upstream TCP mock server closed connection from {addr}")

                while True:
                    conn, addr = s.accept()
                    threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

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
