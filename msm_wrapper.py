"""
HTML Wrapper server for MSM management.
 MSM Link: https://msmhq.com/
 To install as a service in linux, use systemctl. A service file template is provided.
"""

import logging
import urllib.request
from http.server import SimpleHTTPRequestHandler
from base64 import b64encode
import subprocess
import socketserver

AUTH_KEY = ""
CONFIG = None
SERVER = None

def read_config(path="config.txt"):
    config = {}

    # Read all values
    with open(path) as file:
        for line in file:
            com_index = line.find("#")
            if com_index > -1:
                line = line[:com_index]
            if "=" not in line:
                continue
            vals = line.split("=", 1)
            config[vals[0].strip()] = vals[1].strip()

    # Check we have everything we want
    missing_keys = []
    for required_value in ["permitted-resources", "port", "msm-server", "admin-name", "admin-pass", "main-template", "admin-template"]:
        if required_value not in config.keys():
            missing_keys.append(required_value)
    if len(missing_keys) > 0:
        raise ValueError(f"Configuration file did not have all keys! Missing Keys: {missing_keys}\n")

    # Permitted paths should be an array
    paths = config['permitted-resources'].split(',')
    for i in range(len(paths)):
        path = paths[i].strip()
        if path[0] != '/':
            path = '/'+path
        paths[i] = path
    config['permitted-resources'] = paths
    return config

def run_command(command_args):
    try:
        process = subprocess.Popen(command_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (output, err) = process.communicate()
        process.wait()
        return output.decode("utf-8")
    except Exception as e:
        logging.exception(f"Could not execute command {command_args}!")

def get_server_status():
    result = run_command(["msm", SERVER, "status"])
    if not result:
        return False
    return "is running" in result

class AddressReuseServer(socketserver.TCPServer):
    allow_reuse_address = True

class AuthHandler(SimpleHTTPRequestHandler):
    ''' Main class to present webpages and authentication. '''
    def error_bytes(self, title, error):
        return bytes(f"<html><head><h1>{title}</h1></head><body>{error}</h1></body></h1ml>", "utf-8")

    def bind_template_values(self):
        status = "ONLINE" if get_server_status() else "OFFLINE"
        domain_status = "NO_SYNC"
        IP = urllib.request.urlopen('https://ident.me').read().decode('utf8')
        values = template.replace("{{IP}}", IP).replace("{{DOMAIN}}", CONFIG["domain"])
        values = values.replace("{{STATUS}}", status).replace("{{DOMAIN_STATUS}}", domain_status)
        return values
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\Administration\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        ''' Present frontpage with user authentication. '''
        logging.info(self.path)
        if self.path == "/admin":
            if self.headers.get('Authorization') == None:
                self.do_AUTHHEAD()
                self.wfile.write(self.error_bytes("Forbidden", "Not authorized"))
            elif self.headers.get('Authorization') == f'Basic {AUTH_KEY}':
                # Only serve the template
                self.do_HEAD()
                self.wfile.write(bytes("<html><head><h1>Admin Area</h1></head></html>", "utf-8"))
            else:
                self.do_AUTHHEAD()
                self.wfile.write(self.error_bytes("Forbidden", "Not authorized."))
        else:
            if self.path in CONFIG["permitted-resources"]:
                super().do_GET()
            else:
                self.do_HEAD()
                page = self.bind_template_values()
                self.wfile.write(bytes(page, "utf-8"))

    def do_POST(self):
        # No posting allowed
        self.send_response(403)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(self.error_bytes("Not Allowed", "Request type not allowed."))

if __name__ == "__main__":
    logging.info("Reading config...")
    config=read_config()
    with open(config["main-template"]) as file:
        template = file.read()

    print("Done!")
    print(str(config))
    print(template)

    # Set up socket server
    AUTH_KEY = b64encode(bytes(f"{config['admin-name']}:{config['admin-pass']}", "utf-8")).decode("ISO-8859-1")
    CONFIG = config
    SERVER = config["msm-server"]
    with AddressReuseServer(("", int(config["port"])), AuthHandler) as httpd:
        print("serving at port", int(config["port"]))
        try:
            httpd.serve_forever()
        except Exception as e:
            logging.exception("Exception!")
        logging.info("Closing server...")
        httpd.server_close()
        logging.info("Server done.")
