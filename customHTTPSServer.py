import sys
import socket
import ssl
from BaseHTTPServer import HTTPServer

class CustomHTTPSServer(HTTPServer):

    server_address = ('', 8000)
    address_family = socket.AF_INET6

    # this errohandling surpress socket/ssl related errors
    # specially the SSLError: The read operation timed out
    # because of log opened SSL Sockets due to the request relay
    def handle_error(self, request, client_address):
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)