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

import os, socket, threading, select, sys, traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import fulltest_udp_proto
from fulltest_utils import print_time_log, is_macos_system

serv_dir = ""

def run_udp(port):    
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, \
        fulltest_udp_proto.UDP_BUFF_SIZE * \
        (5 if is_macos_system() else 50)) # max 5MB for mac os

    udp_socket.bind(('127.0.0.1', port))
    
    udp_processor = fulltest_udp_proto.UDPProcessor(serv_dir, udp_socket)
    while True:
        data, addr = udp_socket.recvfrom(fulltest_udp_proto.UDP_SEND_PACKET_LENGTH)
        #print_time_log(('Received UDP from %s:%s' % addr) + " length:" + str(len(data)))
        udp_processor.recv(data, addr)
                

class ServerHandler(BaseHTTPRequestHandler):
    mimedic = [
        ('.html', 'text/html'),
        ('.htm', 'text/html'),
        ('.js', 'application/javascript'),
        ('.css', 'text/css'),
        ('.json', 'application/json'),
        ('.png', 'image/png'),
        ('.jpg', 'image/jpeg'),
        ('.gif', 'image/gif'),
        ('.txt', 'text/plain'),
        ('.avi', 'video/x-msvideo'),
    ]    

    def do_GET(self):

        filepath = urlparse(self.path).path

        if filepath.endswith('/'):
            filepath += 'index.html'
        _, fileext = os.path.splitext(filepath)

        mimetype = None
        sendReply = False
        for e in ServerHandler.mimedic:
            if e[0] == fileext:
                mimetype = e[1]
                sendReply = True
                break

        if sendReply == True: 
            try:
                with open(os.path.realpath(serv_dir + filepath),'rb') as f:
                    content = f.read()
                    self.send_response(200)
                    self.send_header('Content-type',mimetype)
                    self.end_headers()
                    self.wfile.write(content)
            except :
                traceback.print_exc(file=sys.stdout)
                self.send_error(404,'File Not Found: %s' % self.path)

    def do_POST(self) :
        try:
            filepath = urlparse(self.path).path
            content_len = int(self.headers.get('Content-Length'))
            post_body = self.rfile.read(content_len)
            
            with open(os.path.realpath(serv_dir + filepath),'rb') as f:
                content = f.read()
                self.send_response(200)
                self.send_header('Content-type','text/plain')
                self.end_headers()
                if content == post_body[2:]:
                    self.wfile.write(b"OK")
                else:
                    self.wfile.write(b"FAILED")
        except:
            traceback.print_exc(file=sys.stdout)

def run(dir, port):
    if not os.path.exists(dir):
        print_time_log("can't find the directory [" + dir +"]")
        exit(1)
    else:
        global serv_dir
        serv_dir = dir + "/"

    t = threading.Thread(target = run_udp, args = (port,))
    t.daemon = True
    t.start()

    httpd = HTTPServer(('127.0.0.1', port), ServerHandler)
    print_time_log("start fulltest server port: " + str(port))
    httpd.serve_forever()

if __name__ == '__main__':
    print_time_log(__file__ + " args " + str(sys.argv))
    if len(sys.argv) >= 3:  
        run(sys.argv[1], int(sys.argv[2]))
    else:
        run('html', 18080)
