import os
import socket
import ssl
import select
import httplib
import traceback
import urlparse
import threading
import gzip
import zlib
import time
import re
import urlparse
import urlBlacklist
from logger import DebugLogger
from BaseHTTPServer import BaseHTTPRequestHandler
from cStringIO import StringIO
from subprocess import Popen, PIPE

class ProxyRequestHandler(BaseHTTPRequestHandler):

    # override default protocol version to use with BaseHTTPServer
    protocol_version = "HTTP/1.1"
    user_agent = ""
    logger=DebugLogger()
    allow_http= []

    cakey = 'ca/ca.key'
    cacert = 'ca/ca.crt'
    certkey = 'ca/cert.key'
    certdir = 'certs/'

    # override Timeout for http and https connection
    timeout = 5

    # threading lock for tsl connections
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        self.check_for_certificate_files()

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def check_for_certificate_files(self):
        self.certificate_files_okay = (
            os.path.isfile(self.cakey)
            and os.path.isfile(self.cacert)
            and os.path.isfile(self.certkey)
            and os.path.isdir(self.certdir)
        )

    def log_error(self, format, *args):
        # surpress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def do_CONNECT(self):
        if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(self.certkey) and os.path.isdir(self.certdir):
            self.connect_intercept()
        else:
            self.connect_relay()

    def connect_intercept(self):
        hostname = self.path.split(':')[0]
        certpath = "%s/%s.crt" % (self.certdir.rstrip('/'), hostname)

        with self.lock:
            if not os.path.isfile(certpath):
                epoch = "%d" % (time.time() * 1000)
                p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
                p2.communicate()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established'))
        self.end_headers()

        self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get('Proxy-Connection', '')
        if conntype.lower() == 'close':
            self.close_connection = 1
        elif (conntype.lower() == 'keep-alive' and self.protocol_version >= "HTTP/1.1"):
            self.close_connection = 0

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def do_GET(self):
        not_allowed_Files = {
            'javascript',
            'js',

        }

        sensitive_param_names = {
            'uid',
            'name', 'usr', 'user', 'username', 'surname',
            'password', 'pwd', 'pass', 'pw',
            'tel','telephone', 'phone', 'number',
            'street', 'zip', 'gender', 'email', 'mail',
            'code', 'location', 'position', 'country',
            'secret',
            'wpName'
        }

        # deliver the Trust Store
        if self.path == 'http://saferweb.trust/':
            self.send_cacert()
            return

        # deliver the Help Page
        if self.path == 'http://saferweb.help/':
            self.send_help()
            return

        # Check if a domain ist blacklisted ?
        if urlBlacklist.check_url(self.path):
            self.reject_url("The website you are trying to access is considered unsave and is Blacklisted for this Proxy. For your own protection all requests to this Domain are rejected")
            return

        # Check if it is a file and if it is whitelisted
        for file in not_allowed_Files:
            # block unauthorized files from request
            if self.path.endswith(file):
                print "not allowed content detected in request: " + file
                self.reject_url("Javascript is not permited")
                return

        req = self

        # Test for parameters
        unsecure = False
        u = urlparse.urlsplit(req.path)
        if u.query:
            for k, v in urlparse.parse_qsl(u.query, keep_blank_values=True):
                for key in sensitive_param_names:
                    if key in k:
                        unsecure = True



        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        # this is the whole login interception routinl
        if req_body is not None:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')

            if content_type.startswith('application/x-www-form-urlencoded'):
                for k, v in urlparse.parse_qsl(req_body, keep_blank_values=True):

                    if k == "saferWeb":
                        if v == "confirm":
                            unsecure = False
                        if v == "add":
                            self.allow_http.append(req.headers['Host'])
                        break
                    for key in sensitive_param_names:
                        #print "compare "+key+" with "+k+"\n"
                        if key in k:
                            unsecure = True

        if unsecure:
            self.confirm_url(req_body)
            return
        # end login interception routin

        # persist http connections


        req_User_Agent = req.headers.get('User-Agent', 0)
        print "original User_Agent: " + req_User_Agent

        if isinstance(self.connection, ssl.SSLSocket):
            #print "https://%s%s" % (req.headers['Host'], req.path)
            req.path = "https://%s%s" % (req.headers['Host'], req.path)
        else:
            print "https_urls_store: "
            print self.allow_http
            print "end"
            if req.headers['Host'] in self.allow_http:
                self.redirect_https("https://%s" % (req.headers['Host']))
                req.path = "http://%s%s" % (req.headers['Host'], req.path)
            else:
                self.redirect_https("https://%s" % (req.headers['Host']))
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
        if req.headers['Host'] in self.allow_http:
            req.path = "http://%s%s" % (req.headers['Host'], req.path)



        req_body_modified = self.request_handler(req, req_body)

        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urlparse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        print path
        print req.path
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        setattr(req, 'headers', self.filter_headers(req.headers))

        try:
            origin = (scheme, netloc)
            if not origin in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=self.timeout)
                else:
                    self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req.headers))
            res = conn.getresponse()

            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])

            # support streaming
            if res.headers.get('Cache-Control'):
                if not 'Content-Length' in res.headers and 'no-store' in res.headers.get('Cache-Control'):
                    self.response_handler(req, req_body, res, '')
                    setattr(res, 'headers', self.filter_headers(res.headers))
                    self.relay_streaming(res)
                    with self.lock:
                        self.save_handler(req, req_body, res, '')
                    return

            res_body = res.read()
        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.reject_http("https://%s" % (req.headers['Host']))
            print "Exception:"
            traceback.print_exc()
            #self.send_error(502)
            return

        for file in not_allowed_Files:
            # block unauthorized files from request
            if file in res.headers.get('Content-Type', ''):
                print "\nnot allowed content detected in response, will be blockes: " + res.headers.get('Content-Type', '') + "\n"
                self.reject_url("This content is not permitted through seafeWeb proxy")
                return

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified is False:
            self.send_error(403)
            return
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        setattr(res, 'headers', self.filter_headers(res.headers))

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    def relay_streaming(self, res):
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error:
            # connection closed by client
            pass

    do_HEAD = do_GET
    do_POST = do_GET
    do_OPTIONS = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]

        # accept only supported encodings
        if 'Accept-Encoding' in headers:
            ae = headers['Accept-Encoding']
            filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
            headers['Accept-Encoding'] = ', '.join(filtered_encodings)

        return headers

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def reject_url(self, msg):
        self.send_error(900,  msg)

    def redirect_https(self, location):
        print "redirecting to https"
        self.send_response(301, "https enforced")
        self.send_header('Location', location)
        self.send_header('X-Forwarded-Proto', 'https')

    def reject_http(self, location):
        print "Request to " + self.headers['Host'] + ": "+ self.path + "interceptend and stalled: "
        print "return 903: The Website you are trying to access does not support secure connections"
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 903,
                                           "The Website you are trying to access does not support secure connections"))
        self.end_headers()
        self.wfile.write("<body><head></head><body><h1>Request stalled</h1>")
        self.wfile.write("<form action=\"http://" + self.headers['Host'] + "\" method=\"get\">")
        self.wfile.write("<input type=\"hidden\" name=\"saferWeb\" value=\"add\">")
        self.wfile.write(
            "<p>Please confirm that you want to visit the website <br>%s<br> altough, it doesn't support https</p>" % self.headers['Host'])
        self.wfile.write(
            "<input type=\"submit\" value=\"Send request\"> <INPUT Type=\"button\" VALUE=\"Return to previous page\" onClick=\"history.go(-1);return true;\"></form></body>")

    def confirm_url(self, param):
        print "Request to "+ self.headers['Host'] + ": "+self.path +"interceptend and stalled: "
        print "return 901: The Website you are trying to access is requesting some possibly sensitive information, pleate confirm That you want to continue"
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 901, "The Website you are trying to access is requesting some possibly sensitive information, pleate confirm That you want to continue"))
        self.end_headers()
        self.wfile.write("<body><head></head><body><h1>Request stalled</h1>")
        self.wfile.write("<p>to the following address:</p>"+self.headers['Host']+self.path)
        self.wfile.write("<form action=\"https://"+self.headers['Host']+self.path+"\" method=\"post\">")
        self.wfile.write("<input type=\"hidden\" name=\"saferWeb\" value=\"confirm\">")
        self.wfile.write("<p>Please confirm that you want to send the following information:</p><pre>%s</pre>" % '\n'.join("%-20s <input type=\"text\"  name=\"%s\" value=\"%s\"><br>" % (k, k, v) for k, v in urlparse.parse_qsl(param, keep_blank_values=True)))
        self.wfile.write("<input type=\"submit\" value=\"Send request\"> <INPUT Type=\"button\" VALUE=\"Return to previous page\" onClick=\"history.go(-1);return true;\"></form></body>")

    def request_handler(self, req, req_body):
        self.user_agent = req.headers.get('User-Agent', 0)
        self.headers["User-Agent"] = "saferWeb Proxy/0.1 (Anonymous web Proxy)"
        u = urlparse.urlsplit(req.path)
        if u.query:
            print u.query
        pass

    def response_handler(self, req, req_body, res, res_body):
        res.headers["User-Agent"] = self.user_agent
        pass

    def save_handler(self, req, req_body, res, res_body):
        self.logger.print_info(req, req_body, res, res_body)

    def send_help(self):
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 900,
                                           "General saferWeb Help"))
        self.end_headers()
        self.wfile.write("<body><head></head><body><h1>saferWeb Help</h1>")
