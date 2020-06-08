import urllib.request, socket, socks, traceback, os
import threading
from concurrent.futures import ThreadPoolExecutor , as_completed
import fulltest_udp_proto

HOST_URL="127.0.0.1"
REQUEST_COUNT_ONCE = 5
OPEN_URL_TIMOUT = 1
SEND_PACKET_LENGTH = fulltest_udp_proto.SEND_PACKET_LENGTH
UDP_BUFF_SIZE = fulltest_udp_proto.UDP_BUFF_SIZE

request_url_prefix = "http://" + HOST_URL
compare_folder = "html"
enable_log = True
serv_port = 0

def print_log(log):
    if enable_log:
        print(log)

def get_url(url):
    f = urllib.request.urlopen(url, timeout = OPEN_URL_TIMOUT)
    return f.read()

def post_url(url, data):
    data = urllib.parse.urlencode({'d':data}).encode()
    req =  urllib.request.Request(url, data=data)
    f = urllib.request.urlopen(req, timeout = OPEN_URL_TIMOUT)
    return f.read()

def post_file_udp(file, data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket :
            udp_socket.settimeout(1)
            udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, UDP_BUFF_SIZE)

            addr = (HOST_URL, serv_port)

            param = urllib.parse.urlencode({'file':file, 'len':len(data), 'm':'POST'}).encode()
            udp_socket.sendto(param + b'\r\n', addr)
            i = 0
            while i < len(data):
                sent = udp_socket.sendto(data[i:i + SEND_PACKET_LENGTH], addr)
                i = i + sent

            return udp_socket.recv(SEND_PACKET_LENGTH)
    except :
        traceback.print_exc()
        return False

def get_file_udp(file, length):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket :
            udp_socket.settimeout(1)
            udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_BUFF_SIZE)

            addr = (HOST_URL, serv_port)

            param = urllib.parse.urlencode({'file':file, 'len':length, 'm':'GET'}).encode()
            udp_socket.sendto(param + b'\r\n', addr)

            data = b''
            try:
                while len(data) < length:
                    data = data + udp_socket.recv(SEND_PACKET_LENGTH)

                return data
            except:
                print_log("exception occur, data recv length:" + str(len(data)))
                traceback.print_exc() 
    except :
        traceback.print_exc()
        return False

def request_get_file(file, tcp_or_udp):
    try:
        print_log(("[TCP]" if tcp_or_udp else "[UDP]") + " request GET file: " + str(file))
        with open(compare_folder + file, "rb") as f:
            compare_txt = f.read()

            txt = b''
            if tcp_or_udp:
                txt = get_url(request_url_prefix + file)
            else:
                txt = get_file_udp(file, len(compare_txt))

            if txt != compare_txt:
                print_log("file content is not same!!! " + file)
                return False
                
        return True       
    except:
        traceback.print_exc()
        return False

def request_post_file(file, tcp_or_udp):
    try:
        print_log(("[TCP]" if tcp_or_udp else "[UDP]") + " request POST file: " + file)
        with open(compare_folder + file, "rb") as f:
            data = f.read()
            result = None
            if tcp_or_udp : 
                result = post_url(request_url_prefix + file, data)
            else:
                result = post_file_udp(file, data)

            if result != b"OK" :
                print_log("file POST FAILED! " + file + " " + str(result))
                return False
        
        return True
        
    except:
        traceback.print_exc()
        return False

def compare_process(files, executor, get_or_post, tcp_or_udp):
    tasks = []
    for f in files:
        if get_or_post : 
            tasks.append(executor.submit(request_get_file, f, tcp_or_udp))
        else:
            tasks.append(executor.submit(request_post_file, f, tcp_or_udp))

    for result in as_completed(tasks):
        if not result.result():
            return False

    return True


def start_query(socks_port, port, folder, log = True):
    global request_url_prefix
    global compare_folder
    global enable_log
    global serv_port
    
    origin_socket = socket.socket

    # setup socket as socks5 proxy
    if socks_port != 0 :
        socks.set_default_proxy(socks.SOCKS5, HOST_URL, socks_port)
        socket.socket = socks.socksocket

    try:
        request_url_prefix = request_url_prefix + ':' + str(port) + '/'
        compare_folder = folder + '/'
        enable_log = log
        serv_port = port

        # get the main index file
        index = get_url(request_url_prefix).decode("utf-8")
        files = []
        for f in index.splitlines():
            print_log("index file: " + f)
            files.append(f)    

        if len(files) == 0:
            print_log("read index file get error!!")
            return False  
        
        with ThreadPoolExecutor(max_workers = REQUEST_COUNT_ONCE) as executor:
            if not compare_process(files, executor, True, True):
                return False

            if not compare_process(files, executor, False, True):
                return False        

            if not compare_process(files, executor, True, False):
                return False

            if not compare_process(files, executor, False, False):
                return False

        print_log("SUCC")
        return True
    finally:
         socket.socket = origin_socket    

if __name__ == '__main__':
    start_query(1062, 8080, "html")