import time
import BaseHTTPServer
import datetime
from Crypto.PublicKey import RSA
from Crypto import Random
import os.path
import json as simplejson

HOST_NAME = 'localhost'
PORT_NUMBER = 9000
keyDict = {"01012016":"XXXXX"}

class KeyHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def do_Head(s):
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()

    def do_GET(s):
        thisDay = str(datetime.datetime.now().day) + str(datetime.datetime.now().month) + str(
            datetime.datetime.now().year)
        pubKey = None
        if "master" in keyDict:
            pubKey = keyDict["master"]
        else:
            if os.path.isfile("masterKey/publicMasterKey.pem"):
                f = open("masterKey/publicMasterKey.pem", 'rb')
                recoveredPubKey = RSA.importKey(f.read())
                pubKey = recoveredPubKey
                print "Key recovered"
            else:
                print "Error: No Master Key found!"

        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
        print pubKey
        s.wfile.write(pubKey.exportKey())

    def do_POST(s):
        thisDay = str(datetime.datetime.now().day) + str(datetime.datetime.now().month) + str(
            datetime.datetime.now().year)

        content_length = int(s.headers['Content-Length'])
        encryptedAESKey = s.rfile.read(content_length)
        encryptedAESKey = encryptedAESKey.splitlines()[3]

        # Do what you wish with file_content
        encryptedAESKey = encryptedAESKey[2:]
        encryptedAESKey=encryptedAESKey[:-3]
        print "Key erhalten!"
        print "PostContent: "+ encryptedAESKey

        f = open("KeyServer/LogKeys/"+ thisDay +".pem", 'w')
        f.write(encryptedAESKey)
        f.close()

        # Begin the response
        s.send_response(200)


if __name__ == '__main__':

    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), KeyHandler)

    if not os.path.exists("KeyServer/LogKeys/"):
        os.makedirs("KeyServer/LogKeys/")
    if not os.path.exists("masterKey/"):
        os.makedirs("masterKey/")
    if not os.path.isfile("masterKey/publicMasterKey.pem"):
        random_generator = Random.new().read
        key = RSA.generate(2048, random_generator)  # generate pub and priv key
        keyDict["master"] = key.publickey()

        f = open("masterKey/privateMasterKey.pem", 'w')
        f.write(key.exportKey('PEM'))
        f.close()

        f = open("masterKey/publicMasterKey.pem", 'w')
        f.write(key.publickey().exportKey('PEM'))
        f.close()

    if not "master" in keyDict:
        f = open("masterKey/publicMasterKey.pem", 'rb')
        keyDict["master"] = RSA.importKey(f.read())

    print time.asctime(), "Server starts - %s:%s" % (HOST_NAME, PORT_NUMBER)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print time.asctime(), "Server stops - %s:%s" % (HOST_NAME, PORT_NUMBER)