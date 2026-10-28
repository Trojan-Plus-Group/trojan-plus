'''
 This file is part of the Trojan Plus project.
 Trojan is an unidentifiable mechanism that helps you bypass GFW.
 Trojan Plus is derived from original trojan project and writing 
 for more experimental features.
 Copyright (C) 2020 The Trojan Plus Group Authors.

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import os
import socket
import threading
import select
import sys
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import fulltest_udp_proto
from fulltest_utils import print_time_log, is_macos_system

serv_dir = ""


def is_ipv6_host(host):
    return ":" in host


def run_udp(port, bind_host="127.0.0.1", ipv6_v6only=False):
    family = socket.AF_INET6 if is_ipv6_host(bind_host) else socket.AF_INET
    udp_socket = socket.socket(family, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                          fulltest_udp_proto.UDP_BUFF_SIZE *
                          (5 if is_macos_system() else 50))  # max 5MB for mac os
    if family == socket.AF_INET6:
        # Pure IPv6 cases set V6ONLY so an IPv4 client cannot reach this socket.
        # The dual-stack case passes ipv6_v6only=False and accepts v4-mapped peers.
        udp_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1 if ipv6_v6only else 0)

    udp_socket.bind((bind_host, port))

    udp_processor = fulltest_udp_proto.UDPProcessor(serv_dir, udp_socket)
    while True:
        data, addr = udp_socket.recvfrom(
            fulltest_udp_proto.UDP_SEND_PACKET_LENGTH)
        #print_time_log(('Received UDP from %s:%s' % addr) + " length:" + str(len(data)))
        udp_processor.recv(data, addr)


class ServerHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        filepath = urlparse(self.path).path

        if filepath.endswith('/'):
            filepath += 'index.html'

        try:
            content = ''
            with open(os.path.realpath(serv_dir + filepath), 'rb') as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except:
            traceback.print_exc(file=sys.stdout)
            self.send_error(404, 'File Not Found: %s' % self.path)

    def do_POST(self):
        try:
            filepath = urlparse(self.path).path
            content_len = int(self.headers.get('Content-Length'))
            post_body = self.rfile.read(content_len)

            content = ''
            with open(os.path.realpath(serv_dir + filepath), 'rb') as f:
                content = f.read()

            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            if content == post_body[2:]:
                self.wfile.write(b"OK")
            else:
                self.wfile.write(b"FAILED")
        except:
            traceback.print_exc(file=sys.stdout)


def make_http_server(bind_host, port, ipv6_v6only=False):
    try:
        from http.server import ThreadingHTTPServer
        server_cls = ThreadingHTTPServer
    except ImportError:
        server_cls = HTTPServer

    if not is_ipv6_host(bind_host):
        return server_cls((bind_host, port), ServerHandler)

    v6only_value = 1 if ipv6_v6only else 0

    class V6HTTPServer(server_cls):
        address_family = socket.AF_INET6

        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, v6only_value)
            super().server_bind()

    return V6HTTPServer((bind_host, port), ServerHandler)


def run(dir, port, bind_host="127.0.0.1", ipv6_v6only=False):
    if not os.path.exists(dir):
        print_time_log("can't find the directory [" + dir + "]")
        exit(1)
    else:
        global serv_dir
        serv_dir = dir + "/"

    t = threading.Thread(target=run_udp, args=(port, bind_host, ipv6_v6only))
    t.daemon = True
    t.start()

    httpd = make_http_server(bind_host, port, ipv6_v6only)
    print_time_log("start fulltest server " + bind_host + " port: " + str(port) +
                   (" ipv6_v6only" if ipv6_v6only else ""))
    httpd.serve_forever()


if __name__ == '__main__':
    print_time_log(__file__ + " args " + str(sys.argv))
    if len(sys.argv) >= 3:
        bind_host = sys.argv[3] if len(sys.argv) >= 4 else "127.0.0.1"
        # Optional 5th arg "1" sets IPV6_V6ONLY. Omitted keeps the IPv4 path
        # and a dual-stack IPv6 bind (V6ONLY=0).
        ipv6_v6only = len(sys.argv) >= 5 and sys.argv[4] == "1"
        run(sys.argv[1], int(sys.argv[2]), bind_host, ipv6_v6only)
    else:
        run('html', 18080)
