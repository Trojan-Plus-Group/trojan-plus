import urllib, os, threading, traceback, socket, select
from concurrent.futures import ThreadPoolExecutor , as_completed

SEND_PACKET_LENGTH = 8192
UDP_BUFF_SIZE = 1024 * 1024

def send_get_func(udp_socket, serv_dir, addr, udp_data):
    try:
        with open(os.path.realpath(serv_dir + udp_data.file()),'rb') as f:
            content = f.read()

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as us :
                us.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, UDP_BUFF_SIZE)                
                i = 0
                while i < len(content):
                    sent = us.sendto(content[i:i + SEND_PACKET_LENGTH], addr)
                    i = i + sent                         
                  
    except:
        traceback.print_exc()

class UDPData:    
    def __init__(self, args, data):
        self.args = args
        self.data = data
        self.total_length = int(self.args["len"])

    def append(self, data):
        self.data = self.data + data

    def file(self):
        return self.args["file"]

    def file_length(self):
        return self.total_length

    def method(self):
        return self.args["m"]

    
class UDPProcessor:

    def __init__(self, serv_dir, udp_socket):
        self.serv_dir = serv_dir
        self.executor = ThreadPoolExecutor(max_workers = 5)
        self.udp_socket = udp_socket
        self.recv_map={}

    def recv(self, data, addr):
        udp_data = None
        if addr in self.recv_map:
            udp_data = self.recv_map[addr]
            udp_data.append(data)
        else:
            args_idx = data.index(b'\r\n')
            args = dict(urllib.parse.parse_qsl(data[:args_idx].decode('ascii')))
            udp_data = UDPData(args, data[args_idx + 2:])
            self.recv_map[addr] = udp_data
        
        if udp_data.method() == 'GET' : 
            send_get_func(self.udp_socket, self.serv_dir, addr, udp_data)
        else:
            self.process(addr, self.recv_map[addr])        

    def process(self, addr, udp_data):
        if len(udp_data.data) == udp_data.file_length():
            with open(os.path.realpath(self.serv_dir + udp_data.file()),'rb') as f:
                cmp_content = f.read()
                self.udp_socket.sendto(b'OK' if cmp_content == udp_data.data else b'FAILED', addr)
                self.recv_map.pop(addr)
