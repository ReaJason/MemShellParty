import http.server
import socketserver

PORT = 8000
TARGET_PATH = "/api/v1/data"


class SimpleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == TARGET_PATH:
            try:
                content_length = int(self.headers['Content-Length'])
                post_data_bytes = self.rfile.read(content_length)
                post_data_str = post_data_bytes.decode('utf-8')
                print("-----------------------------\n")
                print(f"Client IP: {self.client_address}")
                print(f"Request Header:\n{self.headers}")
                print(f"Request Body:\n{post_data_str}")
                print("-----------------------------\n")
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response_message = '{"status": "success"}'
                self.wfile.write(response_message.encode('utf-8'))
            except Exception as e:
                print(f"Parse POST failed: {e}")
                self.send_response(500)
        else:
            print("Make sure use " + TARGET_PATH + " rather than " + self.path)
            self.send_response(404)


with socketserver.TCPServer(("", PORT), SimpleHTTPRequestHandler) as httpd:
    print(f"POST request at http://localhost:{PORT}{TARGET_PATH} Listening ")
    httpd.serve_forever()
