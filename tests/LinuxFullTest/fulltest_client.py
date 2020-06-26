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

import urllib.request
import socket
import socks
import traceback
import os
import time
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import fulltest_udp_proto
from fulltest_utils import print_time_log

PARALLEL_REQUEST_COUNT = 5
RECV_DATA_TIMEOUT = 3
UDP_SEND_PACKET_LENGTH = fulltest_udp_proto.UDP_SEND_PACKET_LENGTH
UDP_BUFF_SIZE = fulltest_udp_proto.UDP_BUFF_SIZE

request_url_prefix = "http://"
compare_folder = "html"
enable_log = True
serv_port = 0
request_host_ip = "127.0.0.1"

client_udp_bind_port_start = fulltest_udp_proto.client_udp_bind_port_start


def print_log(log):
    if enable_log:
        print_time_log(log)


def get_url(url):
    f = urllib.request.urlopen(url, timeout=RECV_DATA_TIMEOUT)
    return f.read()


def post_url(url, data):
    data = urllib.parse.urlencode({'d': data}).encode()
    req = urllib.request.Request(url, data=data)
    f = urllib.request.urlopen(req, timeout=RECV_DATA_TIMEOUT)
    return f.read()


def get_file_udp(file, length, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            udp_socket.settimeout(RECV_DATA_TIMEOUT)
            udp_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_BUFF_SIZE)
            fulltest_udp_proto.bind_port(udp_socket, port)

            global request_host_ip
            addr = (request_host_ip, serv_port)

            param = urllib.parse.urlencode(
                {'file': file, 'len': length, 'm': 'GET'}).encode()
            udp_socket.sendto(param + b'\r\n', addr)

            data_arr = []
            recv_length = 0
            try:
                while recv_length < length:
                    data = udp_socket.recv(UDP_SEND_PACKET_LENGTH)
                    recv_length = recv_length + \
                        len(data) - fulltest_udp_proto.UDP_INDEX_HEADER_SIZE
                    data_arr.append(data)

                return fulltest_udp_proto.compose_udp_file_data(data_arr)
            except:
                print_log("exception occur, data recv length: " +
                          str(recv_length) + " port: " + str(port))
                traceback.print_exc(file=sys.stdout)
                return False
    except:
        print_log("get_file_udp [" + file + "] failed!")
        traceback.print_exc(file=sys.stdout)
        return False


def post_file_udp(file, data, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            udp_socket.settimeout(RECV_DATA_TIMEOUT)
            udp_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_SNDBUF, UDP_BUFF_SIZE)
            fulltest_udp_proto.bind_port(udp_socket, port)

            global request_host_ip
            addr = (request_host_ip, serv_port)

            param = urllib.parse.urlencode(
                {'file': file, 'len': len(data), 'm': 'POST'}).encode()
            udp_socket.sendto(param + b'\r\n', addr)
            time.sleep(0.01)

            fulltest_udp_proto.send_udp_file_data(udp_socket, addr, data)

            return udp_socket.recv(UDP_SEND_PACKET_LENGTH)
    except:
        print_log("post_file_udp [" + file + "] failed!")
        traceback.print_exc(file=sys.stdout)
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
                print_log(str(index) + " " + file + " content is not same!!! read from disk length: " +
                          str(len(compare_txt)) + " read from network length: " + (str(len(txt)) if type(txt) is bytes else str(txt)))

                if type(txt) is bytes and len(txt) == len(compare_txt):
                    print_time_log(txt)

                return False

        return True
    except:
        print_log("request_get_file #" + str(index) +
                  " [" + file + "] failed!")
        traceback.print_exc(file=sys.stdout)
        return False


def request_post_file(file, tcp_or_udp, index, udp_port):
    try:
        #print_log(str(index) + (" [TCP]" if tcp_or_udp else " [UDP]") + " request POST file: " + file)
        with open(compare_folder + file, "rb") as f:
            data = f.read()
            result = None
            if tcp_or_udp:
                result = post_url(request_url_prefix + file, data)
            else:
                result = post_file_udp(file, data, udp_port)

            if result != b"OK":
                print_log(str(index) + " file POST FAILED! " +
                          file + " " + str(result))
                return False

        return True

    except:
        print_log("request_post_file #" + str(index) +
                  " [" + file + "] failed!")
        traceback.print_exc(file=sys.stdout)
        return False


def compare_process(files, executor, get_or_post, tcp_or_udp):
    tasks = []
    index = 0
    global client_udp_bind_port_start
    for f in files:
        if get_or_post:
            tasks.append(executor.submit(request_get_file, f,
                                         tcp_or_udp, index, client_udp_bind_port_start))
        else:
            tasks.append(executor.submit(request_post_file, f,
                                         tcp_or_udp, index, client_udp_bind_port_start))
        index = index + 1

        if not tcp_or_udp:
            client_udp_bind_port_start = client_udp_bind_port_start + 1

    for result in as_completed(tasks):
        if not result.result():
            return False

    return True


def start_query(host_ip, socks_port, port, folder, log=True):
    # setup socket as socks5 proxy
    origin_socket = socket.socket
    if socks_port != 0:
        socks.set_default_proxy(socks.SOCKS5, host_ip, socks_port)
        socket.socket = socks.socksocket
        print_time_log("using pysocks version: " + str(socks.__version__))

    try:
        global request_url_prefix
        global request_host_ip
        global compare_folder
        global enable_log
        global serv_port

        request_host_ip = host_ip
        request_url_prefix = 'http://' + host_ip + ':' + str(port) + '/'
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
        with ThreadPoolExecutor(max_workers=PARALLEL_REQUEST_COUNT) as executor:

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
    #start_query("127.0.0.1", 10620, 18080, "html")

    # forward run_type:
    #start_query("127.0.0.1", 0, 10620, "html")

    # for client_tun redirect to local test
    #start_query("188.188.188.188", 0, 18080, "html")

    # for pure fulltest script run
    start_query("127.0.0.1", 0, 18080, "html")
