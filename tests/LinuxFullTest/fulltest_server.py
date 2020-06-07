import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

curdir = ""

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

class ServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):

        filepath = urlparse(self.path).path

        if filepath.endswith('/'):
            filepath += 'index.html'
        _, fileext = os.path.splitext(filepath)

        mimetype = None
        sendReply = False
        for e in mimedic:
            if e[0] == fileext:
                mimetype = e[1]
                sendReply = True
                break

        if sendReply == True: 
            try:
                with open(os.path.realpath(curdir + filepath),'rb') as f:
                    content = f.read()
                    self.send_response(200)
                    self.send_header('Content-type',mimetype)
                    self.end_headers()
                    self.wfile.write(content)
            except :
                self.send_error(404,'File Not Found: %s' % self.path)

    def do_POST(self) :
        filepath = urlparse(self.path).path
        content_len = int(self.headers.get('Content-Length'))
        post_body = self.rfile.read(content_len)

        with open(os.path.realpath(curdir + filepath),'rb') as f:
            content = f.read()
            self.send_response(200)
            self.send_header('Content-type','text/plain')
            self.end_headers()
            if content == post_body[2:]:
                self.wfile.write(b"OK")
            else:
                self.wfile.write(b"FAILED")

def run(dir, port):
    if not os.path.exists(dir):
        print("can't find the directory [" + dir +"]")
        exit(1)
    else:
        global curdir
        curdir = dir + "/"

    httpd = HTTPServer(('', port), ServerHandler)
    httpd.serve_forever()

if __name__ == '__main__':
    run('html', 8080)
