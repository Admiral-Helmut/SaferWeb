from proxyRequestHandler import ProxyRequestHandler
from customHTTPSServer import CustomHTTPSServer

HandlerClass=ProxyRequestHandler
ServerClass=CustomHTTPSServer

server_address = ('', 8000)
httpd = ServerClass(server_address, HandlerClass)

sa = httpd.socket.getsockname()
print "Proxy is available at ", sa[0], "port", sa[1], "\nTo install the Proxies Trust CA visit http://saferweb.trust/"
httpd.serve_forever()

