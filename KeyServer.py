import time
import BaseHTTPServer
import datetime
from Crypto.PublicKey import RSA
from Crypto import Random
import os.path

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
        if thisDay in keyDict:
            pubKey = keyDict[thisDay]
        else:
            if os.path.isfile("publicKeys/"+thisDay + '.pem'):
                f = open("publicKeys/"+thisDay + '.pem', 'rb')
                recoveredPubKey = RSA.importKey(f.read())
                pubKey = recoveredPubKey
                print "Key recovered"
            else:
                random_generator = Random.new().read
                key = RSA.generate(2048, random_generator)  # generate pub and priv key
                keyDict[thisDay] = key.publickey()
                pubKey = key.publickey()

                f = open("privateKeyServer/privateLogKeys/"+thisDay + '.pem', 'w')
                privateKey = key.exportKey('PEM')
                encrypted = keyDict["master"].encrypt(privateKey, 32)
                f.write(encrypted)
                f.close()

                f = open("publicKeys/"+thisDay + '.pem', 'w')
                f.write(key.publickey().exportKey('PEM'))
                f.close()

        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
        print pubKey
        s.wfile.write(pubKey)


if __name__ == '__main__':

    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), KeyHandler)

    if not os.path.exists("privateKeyServer/privateLogKeys/"):
        os.makedirs("privateKeyServer/privateLogKeys/")
    if not os.path.exists("publicKeys/"):
        os.makedirs("publicKeys/")
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