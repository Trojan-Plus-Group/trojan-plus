import urllib.request, socket, socks, traceback, os
import threading
from concurrent.futures import ThreadPoolExecutor , as_completed

HOST_URL="127.0.0.1"
REQUEST_COUNT_ONCE=5
OPEN_URL_TIMOUT = 1

request_url_prefix = "http://" + HOST_URL
compare_folder = "html"
enable_log = True

def print_log(log):
    if enable_log:
        print(log)

def get_url(url):
    f = urllib.request.urlopen(url, timeout = OPEN_URL_TIMOUT)
    return f.read().decode('utf-8')

def post_url(url, data):
    data = urllib.parse.urlencode({'d':data}).encode()
    req =  urllib.request.Request(url, data=data)
    f = urllib.request.urlopen(req, timeout = OPEN_URL_TIMOUT)
    return f.read().decode('utf-8')

def request_get_file(file):
    try:
        print_log("request GET file: " + file)
        txt = get_url(request_url_prefix + file)
        with open(compare_folder + file, "r") as f:
            compare_txt = f.read()
            if txt != compare_txt:
                print_log("file content is not same!!! " + file)
                return False
                
        return True       
    except:
        traceback.print_exc()
        return False

def request_post_file(file):
    try:
        print_log("request POST file: " + file)
        with open(compare_folder + file, "r") as f:
            data = f.read()
            result = post_url(request_url_prefix + file, data)
            if result != "OK" :
                print_log("file POST FAILED! " + file + " " + str(result))
                return False
        
        return True
        
    except:
        traceback.print_exc()
        return False

def compre_porcess(files, executor, get_or_post):
    tasks = []
    for f in files:
        if get_or_post : 
            tasks.append(executor.submit(request_get_file, f))
        else:
            tasks.append(executor.submit(request_post_file, f))

    for result in as_completed(tasks):
        if not result.result():
            return False

    return True
        
def start_query(socks_port, http_port, folder, log = True):
    global request_url_prefix
    global compare_folder
    global enable_log

    # setup socket as socks5 proxy
    if socks_port != 0 :
        socks.set_default_proxy(socks.SOCKS5, HOST_URL, socks_port)
        socket.socket = socks.socksocket

    request_url_prefix = request_url_prefix + ':' + str(http_port) + '/'
    compare_folder = folder + '/'
    enable_log = log

    # get the main index file
    index = get_url(request_url_prefix)    
    files = []
    for f in index.splitlines():
        print_log("index file: " + f)
        files.append(f)    

    if len(files) == 0:
        print_log("read index file get error!!")
        return False  
    
    with ThreadPoolExecutor(max_workers = REQUEST_COUNT_ONCE) as executor:
       if not compre_porcess(files, executor, True):
           return False

       if not compre_porcess(files, executor, False):
           return False      

    print_log("SUCC")
    return True

if __name__ == '__main__':
    start_query(1062, 8080, "html")