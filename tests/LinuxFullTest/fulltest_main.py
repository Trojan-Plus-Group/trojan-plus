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

import sys
import time
import threading
import signal
import os
import psutil
import traceback
import datetime
import argparse
from subprocess import Popen, PIPE
import fulltest_gen_content
import fulltest_server
import fulltest_client
import fulltest_dns
from fulltest_utils import print_time_log, is_macos_system, is_windows_system, is_linux_system


LOCALHOST_IP = "127.0.0.1"

TEST_FILES_DIR = 'html'
TEST_FILES_COUNT = 50
TEST_FILES_SIZE = 8192 * 10

TEST_SERVER_PORT = 18080
TEST_PROXY_PORT = 10620

TEST_INIT_MAX_RSS_IN_KB = 10 * (1024)

TEST_WATING_FOR_RSS_COOLDOWN_TIME_IN_SEC = 11

# initial var for windows
binary_path = "..\\..\\win32-build\\Release\\trojan.exe"

cmd_args = None


def get_cooldown_rss_limit():
    limit = 0
    if is_macos_system():
        limit = 25 * (1024)
    else:
        limit = 30 * (1024)

    if cmd_args.dns and cmd_args.normal:
        limit = limit + limit / 2

    return limit


def start_trojan_plus_process(config):
    print_time_log("start " + config + "...")
    output_log_file = open(config + ".output", "w+")
    process = Popen([binary_path, "-c", config], executable=binary_path, bufsize=1024 * 1024,
                    stdout=output_log_file, stderr=output_log_file,
                    restore_signals=True, universal_newlines=True)
    process.output_log_file = output_log_file
    process.executable_name = sys.executable
    time.sleep(1)
    if process.returncode:
        print_time_log("Cannot start trojan plus! ")
        output_log_file.close()
        return None

    return process


def close_process(process, output_log):
    if process:
        process.output_log_file.flush()
        if is_windows_system():
            process.send_signal(signal.SIGTERM)
        else:
            process.send_signal(signal.SIGINT)
        time.sleep(1)
        process.output_log_file.flush()

        if process.returncode:
            print_time_log(str(process.args) + " closed.")
        else:
            print_time_log(str(process.args) + " killed.")
            process.kill()

        if output_log:
            process.output_log_file.seek(0, 0)
            print_time_log(process.output_log_file.read(), end='')
            print_time_log()

        process.output_log_file.close()


def run_test_server():
    output_log_file = open("config/test_server.output", "w+")
    process = Popen([sys.executable, "fulltest_server.py", TEST_FILES_DIR, str(TEST_SERVER_PORT)],
                    executable=sys.executable, bufsize=1024 * 1024, stdout=output_log_file, stderr=output_log_file,
                    restore_signals=False, universal_newlines=True)
    process.output_log_file = output_log_file
    time.sleep(1)
    if process.returncode:
        print_time_log("Cannot test server!")
        output_log_file.close()
        return None

    return process


def get_process_rss_in_KB(process):
    if process:
        return int(psutil.Process(process.pid).memory_info().rss / 1024)
    else:
        return 0


def main_stage(server_config, client_config, server_balance_config=None, is_foward=False):

    server_balance_process = None
    if server_balance_config:
        server_balance_process = start_trojan_plus_process(
            "config/" + server_balance_config)
        if not server_balance_process:
            close_process(server_balance_process, True)
            return 0

    server_process = start_trojan_plus_process("config/" + server_config)
    client_process = start_trojan_plus_process("config/" + client_config)

    if not server_process or not client_process:
        close_process(server_process, True)
        close_process(client_process, True)
        close_process(server_balance_process, True)
        return 1

    output_log = False
    try:
        print_time_log("done!")

        server_balance_process_init_rss = get_process_rss_in_KB(
            server_balance_process)
        server_process_init_rss = get_process_rss_in_KB(server_process)
        client_process_init_rss = get_process_rss_in_KB(client_process)

        print_time_log("server balance process init RSS: " +
                       "{:,}KB".format(server_balance_process_init_rss))
        print_time_log("server process init RSS: " +
                       "{:,}KB".format(server_process_init_rss))
        print_time_log("client process init RSS: " +
                       "{:,}KB".format(client_process_init_rss))

        print_time_log("testing max init RSS: " +
                       "{:,}KB".format(TEST_INIT_MAX_RSS_IN_KB))

        if server_process_init_rss > TEST_INIT_MAX_RSS_IN_KB \
                or client_process_init_rss > TEST_INIT_MAX_RSS_IN_KB \
                or server_balance_process_init_rss > TEST_INIT_MAX_RSS_IN_KB:
            print_time_log("init RSS error!!")
            output_log = True
            return 1

        if is_foward:
            if not fulltest_client.start_query(LOCALHOST_IP, 0, TEST_PROXY_PORT, TEST_FILES_DIR):
                output_log = True
                return 1
        elif cmd_args.tun:
            if not fulltest_client.start_query("188.188.188.188", 0, TEST_SERVER_PORT, TEST_FILES_DIR):
                output_log = True
                return 1
        else:
            if cmd_args.normal:
                if not fulltest_client.start_query(LOCALHOST_IP, TEST_PROXY_PORT, TEST_SERVER_PORT, TEST_FILES_DIR):
                    output_log = True
                    return 1

            if cmd_args.dns:
                if not fulltest_dns.start_query("127.0.0.1", 3):
                    output_log = True
                    return 1

        print_time_log("server balance process RSS after testing: " +
                       "{:,}KB".format(get_process_rss_in_KB(server_balance_process)))
        print_time_log("server process RSS after testing: " +
                       "{:,}KB".format(get_process_rss_in_KB(server_process)))
        print_time_log("client process RSS after testing: " +
                       "{:,}KB".format(get_process_rss_in_KB(client_process)))

        print_time_log("waiting "+str(TEST_WATING_FOR_RSS_COOLDOWN_TIME_IN_SEC) +
                       " sec (config's udp_timeout+1) for RSS cooldown...")

        time.sleep(TEST_WATING_FOR_RSS_COOLDOWN_TIME_IN_SEC)

        server_balance_process_rss = get_process_rss_in_KB(
            server_balance_process)
        server_process_rss = get_process_rss_in_KB(server_process)
        client_process_rss = get_process_rss_in_KB(client_process)

        print_time_log("server balance process RSS after cooldown: " +
                       "{:,}KB".format(server_balance_process_rss))
        print_time_log("server process RSS after cooldown: " +
                       "{:,}KB".format(server_process_rss))
        print_time_log("client process RSS after cooldown: " +
                       "{:,}KB".format(client_process_rss))

        print_time_log("testing max RSS after cooldown: " +
                       "{:,}KB".format(get_cooldown_rss_limit()))

        if server_process_rss > get_cooldown_rss_limit() \
                or client_process_rss > get_cooldown_rss_limit() \
                or server_balance_process_init_rss > get_cooldown_rss_limit():
            print_time_log("[ERROR] cooldown RSS error!")
            output_log = True
            return 1

        return 0
    except:
        output_log = True
        traceback.print_exc(file=sys.stdout)
    finally:

        if output_log:
            print_time_log(
                "Has got error, wait for udp timeout log to flush...")
            time.sleep(TEST_WATING_FOR_RSS_COOLDOWN_TIME_IN_SEC)

        close_process(client_process, output_log)
        close_process(server_process, output_log)
        close_process(server_balance_process, output_log)

    return 1


def prepare_forward_config(client_config):
    with open("config/" + client_config, "r") as f:
        content = f.read().replace('"client"', '"forward"')
        filename = client_config + '.forward.tmpjson'
        with open("config/" + filename, 'w') as new_f:
            new_f.write(content)
            return filename


def prepare_client_tun_config(client_config):
    with open("config/" + client_config, "r") as f:
        content = f.read().replace('"client"', '"client_tun"')
        filename = client_config + '.client_tun.tmpjson'
        with open("config/" + filename, 'w') as new_f:
            new_f.write(content)
            return filename


def main():
    if cmd_args.genfile:
        size = cmd_args.genfileSize if cmd_args.genfileSize else TEST_FILES_SIZE
        print_time_log('generating ' + str(cmd_args.genfile) +
                       ' test files each ' + str(size) + ' bytes...')
        fulltest_gen_content.gen_files(TEST_FILES_DIR, cmd_args.genfile, size)

    global binary_path
    binary_path = os.path.realpath(cmd_args.binary)
    print_time_log("binary_path == " + binary_path)

    print_time_log("start testing server...")
    test_server_process = run_test_server()
    if not test_server_process:
        return 1
    output_log = False
    print_time_log("done!")
    try:
        if cmd_args.normal or cmd_args.dns:
            print_time_log(
                "start trojan plus in client run_type without pipeline...")
            if main_stage("server_config.json", "client_config.json") != 0:
                output_log = True
                return 1

            print_time_log(
                "start trojan plus in client run_type in pipeline...")
            if main_stage("server_config_pipeline.json", "client_config_pipeline.json",
                          "server_config_pipeline_balance.json") != 0:
                output_log = True
                return 1

            if cmd_args.normal:
                print_time_log(
                    "start trojan plus in forward run_type without pipeline...")
                if main_stage("server_config.json", prepare_forward_config("client_config.json"), is_foward=True) != 0:
                    output_log = True
                    return 1

                print_time_log(
                    "start trojan plus in forward run_type in pipeline...")
                if main_stage("server_config_pipeline.json", prepare_forward_config("client_config_pipeline.json"),
                              "server_config_pipeline_balance.json", is_foward=True, ) != 0:
                    output_log = True
                    return 1

        if cmd_args.tun:
            print_time_log(
                "restart test http server to test client_tun run_type...")
            close_process(test_server_process, False)
            test_server_process = run_test_server()
            if not test_server_process:
                return 1
            print_time_log("done!")

            print_time_log(
                "start trojan plus in client_tun run_type without pipeline...")
            if main_stage("server_config.json", prepare_client_tun_config("client_config.json"), ) != 0:
                output_log = True
                return 1

            print_time_log(
                "start trojan plus in client_tun run_type in pipeline...")
            if main_stage("server_config_pipeline.json", prepare_client_tun_config("client_config_pipeline.json"),
                          "server_config_pipeline_balance.json", ) != 0:
                output_log = True
                return 1

    finally:
        close_process(test_server_process, output_log)

    print_time_log("!!!!! ALL SUCC, GREAT JOB !!!!")
    return 0


if __name__ == "__main__":
    print_time_log(__file__ + " args : " + str(sys.argv))
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", help='path of trojan binary')
    parser.add_argument("-g", "--genfile", help='whether generate testing files and set quantity of files',
                        type=int, nargs='?', const=TEST_FILES_COUNT)
    parser.add_argument("-gs", "--genfileSize", help='generating files\' size',
                        type=int, nargs='?', const=TEST_FILES_SIZE)
    parser.add_argument("-n", "--normal", help=" whether test normal client/forward mode in or not in pipeline",
                        action='store_true', default=False)
    parser.add_argument("-t", "--tun", help=" whether test tun device (mostly for Android)",
                        action='store_true', default=False)
    parser.add_argument("-d", "--dns", help=" whether test dns forwarding",
                        action='store_true', default=False)

    cmd_args = parser.parse_args()
    if not cmd_args.normal and not cmd_args.dns and not cmd_args.tun:
        print("Error: must use -n or -d or -t args\n\n")
        parser.print_help()
        exit(1)

    exit(main())
