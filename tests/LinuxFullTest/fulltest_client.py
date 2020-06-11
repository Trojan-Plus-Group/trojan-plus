import urllib.request, socket, socks, traceback, os, time
import threading
from concurrent.futures import ThreadPoolExecutor , as_completed
import fulltest_udp_proto, fulltest_main

HOST_URL="127.0.0.1"
PARALLEL_REQUEST_COUNT = 5
OPEN_URL_TIMOUT = 1
SEND_PACKET_LENGTH = fulltest_udp_proto.SEND_PACKET_LENGTH
UDP_BUFF_SIZE = fulltest_udp_proto.UDP_BUFF_SIZE

request_url_prefix = "http://" + HOST_URL
compare_folder = "html"
enable_log = True
serv_port = 0

client_udp_bind_port_start = fulltest_udp_proto.client_udp_bind_port_start

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


def get_file_udp(file, length, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket :
            udp_socket.settimeout(1)
            udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_BUFF_SIZE)
            fulltest_udp_proto.bind_port(udp_socket, port)

            addr = (HOST_URL, serv_port)

            param = urllib.parse.urlencode({'file':file, 'len':length, 'm':'GET'}).encode()
            udp_socket.sendto(param + b'\r\n', addr)
            
            data_arr = []
            recv_length = 0
            try:
                while recv_length < length:
                    data = udp_socket.recv(SEND_PACKET_LENGTH)
                    recv_length = recv_length + len(data) - fulltest_udp_proto.UDP_INDEX_HEADER_SIZE
                    data_arr.append(data)

                return fulltest_udp_proto.compose_udp_file_data(data_arr)
            except:
                print_log("exception occur, data recv length: " + str(recv_length) + " port: " + str(port))
                traceback.print_exc()
                return False
    except :
        traceback.print_exc()
        return False

def post_file_udp(file, data, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket :
            udp_socket.settimeout(1)
            udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, UDP_BUFF_SIZE)
            fulltest_udp_proto.bind_port(udp_socket, port)
            
            addr = (HOST_URL, serv_port)

            param = urllib.parse.urlencode({'file':file, 'len':len(data), 'm':'POST'}).encode()
            udp_socket.sendto(param + b'\r\n', addr)
            time.sleep(0.01)

            fulltest_udp_proto.send_udp_file_data(udp_socket, addr, data)

            return udp_socket.recv(SEND_PACKET_LENGTH)
    except :
        traceback.print_exc()
        return 'please check traceback exceptions'


def request_get_file(file, tcp_or_udp, index, udp_port):
    try:
        #print_log(str(index) + (" [TCP]" if tcp_or_udp else " [UDP]") + " request GET file: " + str(file))
        with open(compare_folder + file, "rb") as f:
            compare_txt = f.read()

            txt = b''
            if tcp_or_udp:
                txt = get_url(request_url_prefix + file)
            else:
                txt = get_file_udp(file, len(compare_txt), udp_port)

            if txt != compare_txt:
                print_log(str(index) + " " + file + " content is not same!!! read from disk length: " + \
                    str(len(compare_txt)) + " read from network length: " + (str(len(txt)) if type(txt) is bytes else str(txt)))
                
                if type(txt) is bytes and len(txt) == len(compare_txt):
                    print(txt)

                return False
                
        return True       
    except:
        traceback.print_exc()
        return False

def request_post_file(file, tcp_or_udp, index, udp_port):
    try:
        #print_log(str(index) + (" [TCP]" if tcp_or_udp else " [UDP]") + " request POST file: " + file)
        with open(compare_folder + file, "rb") as f:
            data = f.read()
            result = None
            if tcp_or_udp : 
                result = post_url(request_url_prefix + file, data)
            else:
                result = post_file_udp(file, data, udp_port)

            if result != b"OK" :
                print_log(str(index) + " file POST FAILED! " + file + " " + str(result))
                return False
        
        return True
        
    except:
        traceback.print_exc()
        return False

def compare_process(files, executor, get_or_post, tcp_or_udp):
    tasks = []
    index = 0
    global client_udp_bind_port_start
    for f in files:
        if get_or_post : 
            tasks.append(executor.submit(request_get_file, f, tcp_or_udp, index, client_udp_bind_port_start))
        else:
            tasks.append(executor.submit(request_post_file, f, tcp_or_udp, index, client_udp_bind_port_start))
        index = index + 1

        if not tcp_or_udp:
            client_udp_bind_port_start = client_udp_bind_port_start + 1        

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
        print("pysocks version: " + str(socks.__version__))

    try:
        request_url_prefix = 'http://' + HOST_URL + ':' + str(port) + '/'
        compare_folder = folder + '/'
        enable_log = log
        serv_port = port

        print_log("start query index file....")

        # get the main index file
        index = get_url(request_url_prefix).decode("utf-8")
        files = []
        for f in index.splitlines():
            files.append(f)    

        if len(files) == 0:
            print_log("read index file get error!!")
            return False  
        
        print_log("read index files " + str(len(files)) + " done!")

        print_log("start query....")
        with ThreadPoolExecutor(max_workers = PARALLEL_REQUEST_COUNT) as executor:

            print_log("start query get http...")
            if not compare_process(files, executor, True, True):
                return False
            print_log("finished!")

            time.sleep(1)

            print_log("start query post http...")
            if not compare_process(files, executor, False, True):
                return False        
            print_log("finish!")

            time.sleep(1)

            print_log("start query get udp...")
            if not compare_process(files, executor, True, False):
                return False
            print_log("finish!")

            time.sleep(1)

            print_log("start query post udp...")
            if not compare_process(files, executor, False, False):
                return False
            print_log("finish!!")

        print_log("SUCC")
        return True
    finally:
        socket.socket = origin_socket    

if __name__ == '__main__':
    # client run_type:
    #start_query(10620, 18080, "html")

    # forward run_type:
    #start_query(0, 10620, "html")

    # for pure fulltest script run
    start_query(0, 18080, "html")