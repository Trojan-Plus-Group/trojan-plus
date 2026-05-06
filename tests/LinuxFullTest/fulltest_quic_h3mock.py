"""
Mock UDP server for QUIC h3_upstream fallback testing.

In trojan-plus, QuicProxySession::forward_to_h3_upstream() forwards stream data
via a UDP socket to simulate a real HTTP/3 backend. The server simply receives
a packet and responds with a fixed marker string.
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
        print_time_log(f"h3_upstream UDP mock server starting on port {port}")

        try:
            # Use SOCK_DGRAM for UDP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('127.0.0.1', port))
                print_time_log(f"h3_upstream UDP mock server listening on 127.0.0.1:{port}")

                while True:
                    try:
                        data, addr = s.recvfrom(4096)
                    except ConnectionResetError:
                        # Windows: ICMP port-unreachable feedback from a previous sendto.
                        # Non-fatal for a UDP server — retry.
                        continue
                    if not data:
                        continue

                    print_time_log(f"h3_upstream UDP mock server received {len(data)} bytes from {addr}")

                    # Since it's UDP, we just send a response back to the same address.
                    # Note: We send the raw response text.
                    response = (
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/plain\r\n"
                        "Content-Length: 21\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                        "H3 Upstream Fallback!"
                    )
                    s.sendto(response.encode('utf-8'), addr)
                    print_time_log(f"h3_upstream UDP mock server sent response to {addr}")
        except Exception as e:
            print_time_log(f"h3_upstream UDP mock server runtime error: {e}")
            traceback.print_exc()
            sys.exit(1)

    if __name__ == "__main__":
        main()

except Exception as e:
    print(f"h3_upstream UDP mock server fatal boot error: {e}", flush=True)
    traceback.print_exc()
    sys.exit(1)
