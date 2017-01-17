import os
from pprint import pprint
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
import cipherWhitelist
from logger import DebugLogger
from BaseHTTPServer import BaseHTTPRequestHandler
from cStringIO import StringIO
from subprocess import Popen, PIPE
from functools import partial
from logEncrypter import LogEncrypter

class ProxyRequestHandler(BaseHTTPRequestHandler):

    # override default protocol version to use with BaseHTTPServer
    protocol_version = "HTTP/1.1"
    user_agent = ""
    logger=DebugLogger()
    logEncrypter1 = LogEncrypter()
    allow_http= []
    allow_cipher= []
    cert_pinns= []
    remove_Headers=[
        "If-Modified-Since",
        "If-None-Match",
        "Cache-Control"
    ]

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
        if 'saferweb.help' in self.path:
            sub = urlparse.urlsplit(self.path)
            self.send_help(sub)
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

                    #handle slatted requests
                    if k == "saferWeb":
                        if v == "confirm":
                            unsecure = False
                        if v == "add":
                            print 'adding host '+req.headers['Host']
                            self.allow_http.append(req.headers['Host'])
                        if v == "addC":
                            print 'adding cipher '+req.headers['Host']
                            self.allow_cipher.append(req.headers['Host'])
                        break

                    #handle insecure params
                    for key in sensitive_param_names:
                        #print "compare "+key+" with "+k+"\n"
                        if key in k:
                            unsecure = True

        if unsecure:
            self.confirm_url(req_body)
            return
        # end login interception routin

        # replace User_Agent
        req_User_Agent = req.headers.get('User-Agent', 0)
        print "original User_Agent: " + req_User_Agent

        subpath = ""
        if req.path[0] == '/':
            subpath = req.path
        # redirect all traffic towards https
        if isinstance(self.connection, ssl.SSLSocket):
            req.path = "https://%s%s" % (req.headers['Host'],subpath)
        else:
            if not req.headers['Host'] in self.allow_http:
                self.redirect_https("https://%s%s" % (req.headers['Host'],subpath))
                return

        # for debugging comment in
        #self.allow_http.append("www.chip.de")
        # handle hosts that do not support https:
        if req.headers['Host'] in self.allow_http:
            print "The url "+req.headers['Host']+" is marked as http trusted"
            req.path = "http://%s%s" % (req.headers['Host'],subpath)

        req_body_modified = self.request_handler(req, req_body)

        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urlparse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)

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

            #check ssl connections and there properties
            if isinstance(conn.sock, ssl.SSLSocket) :
                print conn.sock.cipher()
                conn.sock.do_handshake()

                # pinning function
                finterprint = conn.sock.getpeercert(binary_form=False)
                if finterprint in self.cert_pinns:
                    print "fingerprint matched"
                else:
                    if not req.headers['Host'] in self.allow_http:
                        self.cert_pinns.append(conn.sock.getpeercert(binary_form=False))
                    else:
                        self.send_error(905, "Certificate Pinning mismatch")

                #Check if a cipher suite is whitelisted ?
                if cipherWhitelist.blacklist_cipher(conn.sock.cipher()):
                    if not req.headers['Host'] in self.allow_cipher:
                        self.reject_cipher("https://%s" % (req.headers['Host']))
                        return


            version_table = {9: 'HTTP/1.0', 10: 'HTTP/1.0', 11: 'HTTP/1.1'}
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
            if res.status in [301,404]:
                self.reject_http("https://%s" % (req.headers['Host']))
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
        print "Request to " + self.headers['Host'] + ": "+ self.path + " interceptend and stalled: "
        print "return 903: The Website you are trying to access does not support secure connections"
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 903,
                                           "The Website you are trying to access does not support secure connections"))
        self.end_headers()
        self.wfile.write("<body><head></head><body><h1>Request stalled</h1>")
        self.wfile.write("<form action=\"https://" + self.headers['Host'] + "\" method=\"post\">")
        self.wfile.write("<input type=\"hidden\" name=\"saferWeb\" value=\"add\">")
        self.wfile.write(
            "<p>Please confirm that you want to visit the website <br>%s<br> altough, it doesn't support https</p>" % self.headers['Host'])
        self.wfile.write(
            "<input type=\"submit\" value=\"Send request\"> <INPUT Type=\"button\" VALUE=\"Return to previous page\" onClick=\"history.go(-1);return true;\"></form></body>")

    def reject_cipher(self, location):
        print "Request to " + self.headers['Host'] + ": "+ self.path + " interceptend and stalled: "
        print "return 903: The Website you are trying to access does not support secure connections"
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 903,
                                           "The Website you are trying to access uses weak cipher suites"))
        self.end_headers()
        self.wfile.write("<body><head></head><body><h1>Request stalled</h1>")
        self.wfile.write("<form action=\"https://" + self.headers['Host'] + "\" method=\"post\">")
        self.wfile.write("<input type=\"hidden\" name=\"saferWeb\" value=\"addC\">")
        self.wfile.write(
            "<p>Please confirm that you want to visit the website <br>%s<br> altough, it uses weak cipher suites</p>" % self.headers['Host'])
        self.wfile.write(
            "<input type=\"submit\" value=\"Send request\"> <INPUT Type=\"button\" VALUE=\"Return to previous page\" onClick=\"history.go(-1);return true;\"></form></body>")

    def confirm_url(self, param):
        print "Request to "+ self.headers['Host'] + ": "+self.path +" interceptend and stalled: "
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
        for header in self.remove_Headers:
            if self.headers.get(header) is not None:
                del self.headers[header]
        u = urlparse.urlsplit(req.path)
        if u.query:
            print u.query
        pass

    filtered_tags = [
        'script',
        'iframe',
        '%'
    ]

    def response_handler(self, req, req_body, res, res_body):
        res.headers["User-Agent"] = self.user_agent
        res.headers["Host"] = "https://%s" % (req.headers['Host'])
        if req.headers['Host'] in self.allow_http:
            res_body = re.sub(r"http:\/\/", "https://", res_body)
        # comment all scripts, somehow removing doesn't macht all
        for tag in self.filtered_tags:
            res_body = re.sub("<"+tag, "<!--"+tag, res_body)
            res_body = re.sub("</"+tag, "</"+tag+"--", res_body)
        return res_body

    def save_handler(self, req, req_body, res, res_body):
        self.logger.print_info(req, req_body, res, res_body, self.logEncrypter1)

    def send_help(self, sub):
        if sub.path == "/":
            self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 900,
                                               "General saferWeb Help"))
            self.end_headers()
            with open("help.html", 'rb') as f:
                data = f.read()
        else:
            try:
                with open("Sicherheitskonzept-SaferWeb-Dateien"+sub.path, 'rb') as f:
                    data = f.read()
            except Exception as e:
                self.send_error(404, "Not found")
                return

        self.wfile.write(data)
