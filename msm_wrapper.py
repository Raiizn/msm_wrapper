"""
HTML Wrapper server for MSM management.
 MSM Link: https://msmhq.com/
 To install as a service in linux, use systemctl. A service file template is provided.
"""
import collections
import json
import logging
import re
import sys
import urllib.request
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, BaseHTTPRequestHandler
from base64 import b64encode
import subprocess
import socketserver
from typing import Tuple, Union
import unicodedata
from lib import server_pinger
from threading import Thread, Lock
from queue import Queue, Empty
from lib.mapped_queue import MappedQueue

IP = ""
AUTH_KEY = ""
CONFIG = None
SERVER = None
MSM_CONSOLE = None


class MSMConsole:
    @staticmethod
    def enqueue_output(out, queue):
        logging.debug("[MSMConsole] - enqueue_output()")
        for line in iter(out.readline, b''):
            queue.put(line)
        out.close()

    def __init__(self, server, max_lines=600):
        self.server = server
        self.process = None
        self.shared_buffer = Queue()
        self.max_lines = max_lines
        self.line_dict = collections.OrderedDict()
        # self.line_times = collections.deque(maxlen=max_lines)
        self.line_time_heap = MappedQueue()
        self.lines = collections.deque(maxlen=max_lines)
        self.ansi_escape_8bit = re.compile(
            br'(?:\x1B[@-Z\\-_]|[\x80-\x9A\x9C-\x9F]|(?:\x1B\[|\x9B)[0-?]*[ -/]*[@-~])'
        )

    def _remove_control_characters(self, bytes):
        bytes = self.ansi_escape_8bit.sub(b'', bytes)
        str = bytes.decode("utf-8")
        return "".join(ch for ch in str if unicodedata.category(ch)[0] != "C")

    def _copy_from_buffer(self):
        logging.debug("[MSMConsole] - copy_from_buffer()")
        copy = True
        while copy:
            try:
                line = self.shared_buffer.get_nowait()
                if line is not Empty:
                    # If we're at the max lines, pop the earliest one off
                    if len(self.line_time_heap) == self.max_lines:
                        logging.debug("Popping earliest stored line")
                        dt = self.line_time_heap.pop()
                        self.line_dict.pop(dt)

                    # Fix up the line and add it to the tracking
                    line = self._remove_control_characters(line)
                    dt = datetime.utcnow()
                    self.line_time_heap.push(dt)
                    self.line_dict[dt] = line

            except Empty:
                copy = False

    def _reopen_if_needed(self):
        if self.process is None or self.process.poll() is not None:
            try:
                logging.debug("Reopening console...")
                self.open_console()
            except Exception as e:
                logging.exception("Could not open console process", e)
                self.lines.append(f"<ERR> Could not open console process: {e}")

    def get_output(self, from_datetime=None):
        logging.debug("[MSMConsole] - get_output()")

        # Reopen console if needed and open from the buffer
        self._reopen_if_needed()
        self._copy_from_buffer()

        # Grab all lines from the given datetime onward
        if from_datetime is None:
            from_datetime = datetime.min
        max = len(self.line_time_heap)
        values = []
        i = self.line_time_heap.binary_search(from_datetime)
        while i < max:
            dt = self.line_time_heap.h[i]
            values.append(self.line_dict[dt])
            i += 1

        return values

    def open_console(self):
        logging.debug("[MSMConsole] - open_console()")
        command = ["msm", self.server, "console"]
        logging.info(f"Starting up MSM console with command {command}")

        _, self.process = MSMWrapperServer.run_command(command, blocking=False)
        t = Thread(target=MSMConsole.enqueue_output, args=(self.process.stdout, self.shared_buffer))
        t.daemon = True
        t.start()

    def close(self):
        logging.debug("[MSMConsole] - close()")
        logging.info("Detaching from screen session.")
        if self.process is not None and self.process.stdin:
            self.process.stdin.write([0x21, 0x24])  # Detach from screen session setup by MSM


class MSMWrapperServer(SimpleHTTPRequestHandler):
    info_mutex = Lock()

    """ Main class to present webpages and authentication. """
    def __init__(self, request, client_address, server):
        with open(CONFIG["main-template"]) as file:
            self.template = file.read()
        with open(CONFIG["admin-template"]) as file:
            self.admin_template = file.read()
        SimpleHTTPRequestHandler.__init__(self, request, client_address, server)

    @staticmethod
    def error_bytes(title, error):
        return bytes(f"<html><head><h1>{title}</h1></head><body>{error}</h1></body></h1ml>", "utf-8")

    @staticmethod
    def bind_template_values(contents: str):
        online, server = MSMWrapperServer.get_server_info()
        status = MSMWrapperServer.get_server_status((online, server))

        players = server.players.online if online and server.accepting_connections else 0
        max_players = server.players.max if online and server.accepting_connections else 0

        domain_status = "NO_SYNC"
        values = contents.replace("{{IP}}", IP).replace("{{DOMAIN}}", CONFIG["domain"])
        values = values.replace("{{STATUS}}", status).replace("{{DOMAIN_STATUS}}", domain_status)
        values = values.replace("{{PLAYERS}}", str(players)).replace("{{MAX_PLAYERS}}", str(max_players))
        return values

    @staticmethod
    def get_server_info() -> Tuple[bool, Union[server_pinger.Server, None]]:
        result, _ = MSMWrapperServer.run_command(["msm", SERVER, "status"])
        if result is None or "is running" not in result:  # MSM says it's down
            return False, None

        # MSM says the server is running so grab the info from the pinger.
        # note: The server may refuse the connection when initializing. This is flagged in the returned object
        MSMWrapperServer.info_mutex.acquire()
        try:
            ping_result = server_pinger.ping("127.0.0.1")
        finally:
            MSMWrapperServer.info_mutex.release()
        return True, ping_result

    @staticmethod
    def get_server_status(info: Tuple[bool, Union[server_pinger.Server, None]]) -> str:
        online, server = info
        if not online:
            return "offline"
        if online and server.accepting_connections:
            return "online"
        else:
            return "initializing"

    @staticmethod
    def run_command(command_args, blocking=True) -> Tuple[str, Union[None, subprocess.Popen]]:
        try:
            if blocking:
                process = subprocess.Popen(command_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                (output, err) = process.communicate()
                process.wait()
                return output.decode("utf-8"), process
            else:
                process = subprocess.Popen(command_args,
                                           stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT,
                                           start_new_session=True)
                return "", process
        except Exception:
            logging.exception(f"Could not execute command {command_args}!")
            return "", None


    """"""""""""""""""""""""""""""
    """    REQUEST HANDLING    """
    """"""""""""""""""""""""""""""
    def do_HEAD(self, content_type='text/html'):
        self.send_response(200)
        self.send_header('Content-type', content_type)
        self.end_headers()

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\Administration\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def get_API(self, path: str, resource: dict):
        logging.debug(f"API Request for {resource} under {path}")
        self.do_HEAD('application/json')
        if path in self.api_routes:
            print("Serving up API result")
            contents = self.api_routes[path](self, resource)  # noqa
            if isinstance(contents, str):
                contents = {"value": contents}
            if contents is not None:
                self.wfile.write(bytes(json.dumps(contents), 'utf-8'))
            else:
                logging.warning(f"Got empty API response for {path}")
        self.end_headers()

    def do_GET(self):
        path = self.path
        path = path[:-1] if path.endswith("/") else path
        result = urlparse(path)
        resource = {
            "path": result.path,
            "params": result.params,
            "query": parse_qs(result.query),
            "fragment": result.fragment
        }
        logging.info(f"Request: {result}")

        if path.startswith("/admin"):
            path = path[len("/admin"):]
            if self.headers.get('Authorization') is None or self.headers.get('Authorization') != f'Basic {AUTH_KEY}':
                self.do_AUTHHEAD()
                self.wfile.write(self.error_bytes("Forbidden", "Not authorized"))
            else:
                if path.startswith("/api"):
                    self.get_API(path[len("/api"):], resource)
                else:
                    # Only serve the template
                    self.do_HEAD()
                    page = self.bind_template_values(self.admin_template)
                    # page = self.admin_template
                    self.wfile.write(bytes(page, "utf-8"))
        elif path.startswith("/api"):
            self.get_API(self.path[4:], resource)
        else:
            if path in CONFIG["permitted-resources"]:
                super().do_GET()
            else:
                self.do_HEAD()
                page = self.bind_template_values(self.template)
                self.wfile.write(bytes(page, "utf-8"))

    def do_POST(self):
        # No posting allowed
        self.send_response(403)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(self.error_bytes("Not Allowed", "Request type not allowed."))


    """"""""""""""""""""""""""""""
    """     API HANDLING      """
    """"""""""""""""""""""""""""""
    def check_api_auth(self):
        if self.headers.get('Authorization') is None or self.headers.get('Authorization') != f'Basic {AUTH_KEY}':
            value = {"error": "Forbidden"}
            self.wfile.write(bytes(json.dumps(value), 'utf-8'))
            return False
        return True

    def get_status(self, _):
        online, server = self.get_server_info()
        return self.get_server_status((online, server))

    def get_players(self, _):
        online, server = self.get_server_info()
        result = {"online": 0, "max": 0}
        if online:
            result = {"online": server.players.online,
                      "max": server.players.max}
        return result

    def get_ip(self, _):
        return IP

    def get_console(self, resource):
        if not self.check_api_auth():
            return
        query = resource["query"]

        dt = datetime.min
        if "since_utc_ts" in query:
            try:
                timestamp = int(query["since_utc_ts"])
                dt = datetime.utcfromtimestamp(timestamp)
            except:
                logging.info(f"Invalid query given to get_console(): {query}")
        return {"output": MSM_CONSOLE.get_output(dt)}

    def start_server(self, _):
        if not self.check_api_auth():
            return
        self.run_command(["msm", SERVER, "start"], blocking=False)
        return "success"

    def stop_server(self, _):
        if not self.check_api_auth():
            return
        self.run_command(["msm", SERVER, "stop"], blocking=False)
        return "success"

    def restart_server(self, _):
        if not self.check_api_auth():
            return
        self.run_command(["msm", SERVER, "restart"], blocking=False)
        return "success"

    # API Routing
    api_routes = {"/status": get_status,
                  "/players": get_players,
                  "/ip": get_ip,
                  "/console": get_console,
                  "/start": start_server,
                  "/restart": restart_server,
                  "/stop": stop_server}


class AddressReuseServer(socketserver.TCPServer):
    allow_reuse_address = True


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
    for required_value in ["permitted-resources", "port", "msm-server", "admin-name", "admin-pass", "main-template",
                           "admin-template"]:
        if required_value not in config.keys():
            missing_keys.append(required_value)
    if len(missing_keys) > 0:
        raise ValueError(f"Configuration file did not have all keys! Missing Keys: {missing_keys}\n")

    # Permitted paths should be an array
    paths = config['permitted-resources'].split(',')
    for i in range(len(paths)):
        path = paths[i].strip()
        if path[0] != '/':
            path = '/' + path
        paths[i] = path
    config['permitted-resources'] = paths
    return config


if __name__ == "__main__":
    if "-v" in sys.argv or "--verbose" in sys.argv:
        logging.getLogger().setLevel(logging.DEBUG)
    logging.info("Reading config and template files")
    config = read_config()

    logging.info("Done!")
    print_config = dict(config)
    print_config["admin-pass"] = "<redacted>"
    logging.info(str(print_config))

    # Configure globals for the requests object to access
    IP = urllib.request.urlopen('https://ident.me').read().decode('utf8')  # Get IP from external API
    AUTH_KEY = b64encode(bytes(f"{config['admin-name']}:{config['admin-pass']}", "utf-8")).decode("ISO-8859-1")
    CONFIG = config
    SERVER = config["msm-server"]
    MSM_CONSOLE = MSMConsole(SERVER)

    # Set up socket server
    with AddressReuseServer(("", int(config["port"])), MSMWrapperServer) as httpd:
        print(f"Serving requests at port {int(config['port'])}")
        print(f"MSM Server: {SERVER}")
        try:
            httpd.serve_forever()
        except Exception:
            logging.exception("Exception!")
        httpd.server_close()
        MSM_CONSOLE.close()
