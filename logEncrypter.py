import datetime

from Crypto.PublicKey import RSA
from Crypto import Random

class LogEncrypter:

    keyDict = {"01012000": "XXXXX"}

    def __init__(self):
        pass


    def encrypted_logging(logText):
        thisDay = str(datetime.datetime.now().day) + str(datetime.datetime.now().month) + str(
            datetime.datetime.now().year)
        key = None
        if thisDay in self.keyDist :
            key = self.keyDict[thisDay]
        else:
            random_generator = Random.new().read
            key = RSA.generate(2048, random_generator)  # generate pub and priv key
            self.keyDict[thisDay] = key
            f = open(thisDay + '.pem', 'w')
            f.write(key.exportKey('PEM'))
            f.close()

        publickey = key.publickey()  # pub key export for exchange
        encrypted = publickey.encrypt(logText, 32)
        logtime = str(datetime.datetime.now().hour) + str(datetime.datetime.now().minute) + str(
            datetime.datetime.now().second) + str(datetime.datetime.now().microsecond)
        f = open(thisDay + logtime + '.txt', 'wb')
        f.write(str(encrypted))  # write ciphertext to file
        f.close()
