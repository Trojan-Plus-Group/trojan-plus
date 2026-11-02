"""
Controllable UDP and TCP relays for network outage and rebinding simulation.
Used by QUIC network recovery tests.
"""

import os
import select
import socket
import threading
import time


class UdpRelay:
    """
    A controllable UDP relay between a client and a server.
    Supports blackholing (dropping all packets) and NAT rebinding
    (allocating a new local upstream port on resume).
    """

    def __init__(self, listen_port=0, target_ip="127.0.0.1", target_port=14651, logger=None):
        self.target_ip = target_ip
        self.target_port = target_port
        self.logger = logger

        self.ls = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", listen_port or 0))
        self.listen_port = self.ls.getsockname()[1]

        self.us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.us.bind(("127.0.0.1", 0))

        self.stale_us = []
        self.client_addr = None
        self.paused = False
        self.running = True
        self.lock = threading.Lock()

        self.pkt_to_server = 0
        self.pkt_to_client = 0
        self.pkt_dropped = 0
        self.stale_hits = 0

        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def pause(self):
        """Drop all packets in both directions."""
        with self.lock:
            self.paused = True
            if self.logger:
                self.logger(f"UdpRelay paused at {time.time():.3f}")

    def resume(self, rebind=False):
        """Resume forwarding packets. If rebind=True, change the upstream socket."""
        with self.lock:
            if rebind:
                self.stale_us.append(self.us)
                self.us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.us.bind(("127.0.0.1", 0))
                if self.logger:
                    self.logger(f"UdpRelay resumed WITH REBIND -> {self.us.getsockname()[1]} at {time.time():.3f}")
            else:
                if self.logger:
                    self.logger(f"UdpRelay resumed at {time.time():.3f}")
            self.paused = False

    def rebind(self):
        """Rebind the upstream socket to a new ephemeral port."""
        with self.lock:
            self.stale_us.append(self.us)
            self.us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.us.bind(("127.0.0.1", 0))
            if self.logger:
                self.logger(f"UdpRelay rebind -> {self.us.getsockname()[1]} at {time.time():.3f}")

    def get_upstream_port(self):
        with self.lock:
            return self.us.getsockname()[1]

    def _run(self):
        while self.running:
            with self.lock:
                socks = [self.ls, self.us] + self.stale_us
                paused = self.paused
                us = self.us

            try:
                r, _, _ = select.select(socks, [], [], 0.05)
            except Exception:
                break

            for s in r:
                try:
                    data, addr = s.recvfrom(65535)
                except Exception:
                    continue

                if s in self.stale_us:
                    with self.lock:
                        self.stale_hits += 1
                    continue

                if paused:
                    with self.lock:
                        self.pkt_dropped += 1
                    continue

                if s is self.ls:
                    with self.lock:
                        self.client_addr = addr
                        self.pkt_to_server += 1
                    try:
                        us.sendto(data, (self.target_ip, self.target_port))
                    except Exception:
                        pass
                else:  # s is self.us (response from server)
                    with self.lock:
                        dst = self.client_addr
                        self.pkt_to_client += 1
                    if dst:
                        try:
                            self.ls.sendto(data, dst)
                        except Exception:
                            pass

    def stop(self):
        self.running = False
        self.thread.join(timeout=1.0)
        try:
            self.ls.close()
        except Exception:
            pass
        try:
            self.us.close()
        except Exception:
            pass
        for s in self.stale_us:
            try:
                s.close()
            except Exception:
                pass


class TcpRelay:
    """
    A controllable TCP relay between a client and a server.
    Can pause traffic by closing/dropping connections.
    """

    def __init__(self, listen_port=0, target_ip="127.0.0.1", target_port=14651, logger=None):
        self.target_ip = target_ip
        self.target_port = target_port
        self.logger = logger

        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("127.0.0.1", listen_port or 0))
        self.listen_port = self.server_sock.getsockname()[1]
        self.server_sock.listen(128)

        self.paused = False
        self.running = True
        self.active_conns = []
        self.lock = threading.Lock()

        self.accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.accept_thread.start()

    def pause(self):
        with self.lock:
            self.paused = True
            if self.logger:
                self.logger(f"TcpRelay paused at {time.time():.3f}")
            # Cut all active connections
            for c1, c2 in self.active_conns:
                try:
                    c1.close()
                except Exception:
                    pass
                try:
                    c2.close()
                except Exception:
                    pass
            self.active_conns.clear()

    def resume(self, rebind=False):
        with self.lock:
            self.paused = False
            if self.logger:
                self.logger(f"TcpRelay resumed at {time.time():.3f}")

    def _accept_loop(self):
        while self.running:
            try:
                r, _, _ = select.select([self.server_sock], [], [], 0.1)
                if not r:
                    continue
                client_sock, _ = self.server_sock.accept()
            except Exception:
                break

            with self.lock:
                if self.paused:
                    # Blackhole: close immediately or discard
                    client_sock.close()
                    continue

            try:
                upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                upstream_sock.connect((self.target_ip, self.target_port))
            except Exception:
                client_sock.close()
                continue

            with self.lock:
                pair = (client_sock, upstream_sock)
                self.active_conns.append(pair)

            t = threading.Thread(target=self._forward_pair, args=(client_sock, upstream_sock), daemon=True)
            t.start()

    def _forward_pair(self, c1, c2):
        try:
            while self.running:
                with self.lock:
                    if self.paused:
                        break
                r, _, _ = select.select([c1, c2], [], [], 0.1)
                for s in r:
                    other = c2 if s is c1 else c1
                    data = s.recv(65536)
                    if not data:
                        return
                    other.sendall(data)
        except Exception:
            pass
        finally:
            with self.lock:
                try:
                    self.active_conns.remove((c1, c2))
                except ValueError:
                    pass
            try:
                c1.close()
            except Exception:
                pass
            try:
                c2.close()
            except Exception:
                pass

    def stop(self):
        self.running = False
        self.pause()
        try:
            self.server_sock.close()
        except Exception:
            pass
        self.accept_thread.join(timeout=1.0)
