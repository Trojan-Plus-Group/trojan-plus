import sys, time, threading, signal, os
from subprocess import Popen, PIPE
import fulltest_gen_content, fulltest_server, fulltest_client

TEST_FILES_DIR = 'html'
TEST_FILES_COUNT = 50
TEST_FILES_SIZE = 8192 * 10

TEST_SERVER_PORT = 8080
TEST_PROXY_PORT = 10620

# initial var for windows
binary_path = "..\\..\\win32-build\\Release\\trojan.exe"

def start_trojan_plus_runing(config):
    print("start " + config + "...")
    process = Popen([binary_path, "-c", config], executable = binary_path, bufsize = 1024 * 1024)
    time.sleep(1)
    if process.returncode:
        print("Cannot start trojan plus: ")
        for f in process.stdout.readlines():
            print(str(f).replace("\r",""), end = '')
        for f in process.stderr.readlines():
            print(str(f).replace("\r",""), end = '')
        return None

    return process

def close_process(process, output_log):
    if process:
        process.send_signal(signal.SIGTERM)
        time.sleep(1)
        if process.returncode:
            print("closed.")
        else:
            print("killed.")
            process.kill()

        if output_log:
            for f in process.stdout.readlines():
                print(f.decode("ascii").replace("\r",""), end = '')
            for f in process.stderr.readlines():
                print(f.decode("ascii").replace("\r",""), end = '')


def run_test_server():
    process = Popen([sys.executable, "fulltest_server.py", TEST_FILES_DIR, str(TEST_SERVER_PORT)], 
                    executable = sys.executable,bufsize = 1024 * 1024)
    time.sleep(1)
    if process.returncode:
        print("Cannot test server: ")
        for f in process.stdout.readlines():
            print(f.decode("ascii").replace("\r",""), end = '')
        for f in process.stderr.readlines():
            print(f.decode("ascii").replace("\r",""), end = '')
        return None

    return process

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
    
    print("done!")
    
    print("start trojan plus in client run_type without pipeline...")

    server_process = start_trojan_plus_runing("config/server_config.json")
    client_process = start_trojan_plus_runing("config/client_config.json")

    if not server_process or not client_process:
        close_process(server_process, True)
        close_process(client_process, True)
        close_process(test_server_process, True)
        return 1
    
    output_log = False
    try:
        print("done!")

        if not fulltest_client.start_query(TEST_PROXY_PORT, TEST_SERVER_PORT, TEST_FILES_DIR):
            output_log = True
            return 1
    finally:
        close_process(server_process, output_log)
        close_process(client_process, output_log)
        close_process(test_server_process, output_log)

    return 0
    
if __name__ == "__main__":
    print(__file__ + " args : " + str(sys.argv))
    if len(sys.argv) < 2:
        print("please set trojan plus binary path!")
        exit(1)
    else:
        exit(main())