import sys, time, threading, signal, os, psutil
from subprocess import Popen, PIPE
import fulltest_gen_content, fulltest_server, fulltest_client

TEST_FILES_DIR = 'html'
TEST_FILES_COUNT = 50
TEST_FILES_SIZE = 8192 * 10

TEST_SERVER_PORT = 8080
TEST_PROXY_PORT = 10620

TEST_INIT_MAX_RSS_IN_KB = 8 * (1024)
TEST_TESTING_MAX_RSS_IN_KB = 20 * (1024)

TEST_WATING_FOR_RSS_COOLDOWN_TIME_IN_SEC = 11

# initial var for windows
binary_path = "..\\..\\win32-build\\Release\\trojan.exe"

def start_trojan_plus_runing(config):
    print("start " + config + "...")
    output_log_file = open(config + ".output", "w+")
    process = Popen([binary_path, "-c", config], executable = binary_path, bufsize = 1024 * 1024, 
                    stdout = output_log_file, stderr = output_log_file,
                    restore_signals = False, universal_newlines = True)
    process.output_log_file = output_log_file
    process.executable_name = sys.executable
    time.sleep(1)
    if process.returncode:
        print("Cannot start trojan plus! ")
        output_log_file.close()
        return None

    return process

def close_process(process, output_log):
    if process:
        process.send_signal(signal.SIGTERM)
        time.sleep(1)
        if process.returncode:
            print(str(process.args) + " closed.")
        else:
            print(str(process.args) + " killed.")
            process.kill()

        if output_log :
            process.output_log_file.flush()
            process.output_log_file.seek(0,0)
            print(process.output_log_file.read(), end = '')
            print()
            
        process.output_log_file.close()

def run_test_server():
    output_log_file = open("config/test_server.output", "w+")
    process = Popen([sys.executable, "fulltest_server.py", TEST_FILES_DIR, str(TEST_SERVER_PORT)], 
                    executable = sys.executable, bufsize = 1024 * 1024, stdout = output_log_file, stderr = output_log_file,
                    restore_signals = False, universal_newlines = True)
    process.output_log_file = output_log_file
    time.sleep(1)
    if process.returncode:
        print("Cannot test server!")
        output_log_file.close()
        return None

    return process


def get_process_rss_in_KB(process):
    if process:
        return int(psutil.Process(process.pid).memory_info().rss / 1024)
    else:
        return 0

def main_stage(server_config, client_config, server_balance_config = None, is_foward = False):

    server_balance_process = None
    if server_balance_config:
        server_balance_process = start_trojan_plus_runing("config/" + server_balance_config)
        if not server_balance_process:
            close_process(server_balance_process, True)
            return 0

    server_process = start_trojan_plus_runing("config/" + server_config)
    client_process = start_trojan_plus_runing("config/" + client_config)

    if not server_process or not client_process:
        close_process(server_process, True)
        close_process(client_process, True)
        close_process(server_balance_process, True)        
        return 1
    
    output_log = False
    try:
        print("done!")

        server_balance_process_init_rss = get_process_rss_in_KB(server_balance_process)
        server_process_init_rss = get_process_rss_in_KB(server_process)
        client_process_init_rss = get_process_rss_in_KB(client_process)        

        print("server balance process init RSS: " + "{:,}KB".format(server_balance_process_init_rss))
        print("server process init RSS: " + "{:,}KB".format(server_process_init_rss))
        print("client process init RSS: " + "{:,}KB".format(client_process_init_rss))

        print("testing max init RSS: " + "{:,}KB".format(TEST_INIT_MAX_RSS_IN_KB))

        if server_process_init_rss > TEST_INIT_MAX_RSS_IN_KB \
        or client_process_init_rss > TEST_INIT_MAX_RSS_IN_KB \
        or server_balance_process_init_rss > TEST_INIT_MAX_RSS_IN_KB:
            print("init RSS error!!")
            output_log = True
            return 1

        if is_foward:
            if not fulltest_client.start_query(0, TEST_PROXY_PORT, TEST_FILES_DIR):
                output_log = True
                return 1
        else:
            if not fulltest_client.start_query(TEST_PROXY_PORT, TEST_SERVER_PORT, TEST_FILES_DIR):
                output_log = True
                return 1

        print("server balance process RSS after testing: " + "{:,}KB".format(get_process_rss_in_KB(server_balance_process)))
        print("server process RSS after testing: " + "{:,}KB".format(get_process_rss_in_KB(server_process)))
        print("client process RSS after testing: " + "{:,}KB".format(get_process_rss_in_KB(client_process)))

        print("waiting "+str(TEST_WATING_FOR_RSS_COOLDOWN_TIME_IN_SEC)+" sec for RSS cooldown...")

        time.sleep(TEST_WATING_FOR_RSS_COOLDOWN_TIME_IN_SEC)

        server_balance_process_rss = get_process_rss_in_KB(server_balance_process)
        server_process_rss = get_process_rss_in_KB(server_process)
        client_process_rss = get_process_rss_in_KB(client_process)

        print("server balance process RSS after cooldown: " + "{:,}KB".format(server_balance_process_rss))
        print("server process RSS after cooldown: " + "{:,}KB".format(server_process_rss))
        print("client process RSS after cooldown: " + "{:,}KB".format(client_process_rss))

        print("testing max RSS after cooldown: " + "{:,}KB".format(TEST_TESTING_MAX_RSS_IN_KB))

        if server_process_rss > TEST_TESTING_MAX_RSS_IN_KB \
        or client_process_rss > TEST_TESTING_MAX_RSS_IN_KB \
        or server_balance_process_init_rss > TEST_TESTING_MAX_RSS_IN_KB:
            print("cooldown RSS error!")
            output_log = True
            return 1

        return 0
    finally:
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

def main():
    if sys.argv.count('-g') != 0:
        print("generating testing files....")
        fulltest_gen_content.gen_files(TEST_FILES_DIR, TEST_FILES_COUNT, TEST_FILES_SIZE)

    global binary_path
    binary_path = os.path.realpath(sys.argv[1])
    print("binary_path == " + binary_path)

    print("start testing server...")
    test_server_process = run_test_server()
    if not test_server_process:
        return 1
    output_log = False
    print("done!")
    try:
        print("start trojan plus in client run_type without pipeline...")
        if main_stage("server_config.json", "client_config.json") != 0:
            output_log = True
            return 1

        print("start trojan plus in client run_type in pipeline...")
        if main_stage("server_config_pipeline.json", "client_config_pipeline.json", "server_config_pipeline_balance.json") != 0:
            output_log = True
            return 1
        

        print("start trojan plus in forward run_type without pipeline...")
        if main_stage("server_config.json", prepare_forward_config("client_config.json"), is_foward = True) != 0:
            output_log = True
            return 1

        print("start trojan plus in forward run_type in pipeline...")
        if main_stage("server_config_pipeline.json", prepare_forward_config("client_config_pipeline.json"), "server_config_pipeline_balance.json", is_foward = True) != 0:
            output_log = True
            return 1     
    finally:
        close_process(test_server_process, output_log)

    print("!!!!! ALL SUCC, GREAT JOB !!!!")
    return 0
    
if __name__ == "__main__":
    print(__file__ + " args : " + str(sys.argv))
    if len(sys.argv) < 2:
        print("please set trojan plus binary path!")
        exit(1)
    else:
        exit(main())