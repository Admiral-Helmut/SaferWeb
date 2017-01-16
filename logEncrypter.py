import datetime

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
import requests
import json
import os

AES_KEY_LEN = 32
AES_IV = 'IV13579IV2468IV1'  # 128 Bit Initialisierungsvektor
KEY_SERVER = 'http://localhost:9000'


class LogEncrypter(object):
    def __init__(self):
        self.keyDict = {"01012000": "XXXXX"}
        pass

    def encrypted_logging(self, logText):
        thisDay = str(datetime.datetime.now().day) + str(datetime.datetime.now().month) + str(
            datetime.datetime.now().year)

        # Get Public RSA Key from KeyServer
        r = requests.get(KEY_SERVER)
        # print r.text
        recoveredPubKey = RSA.importKey(r.text)

        # Get or generate daily AES Key to encrypt Log
        if not thisDay in self.keyDict:
            newDailyAESKey = Random.new().read(AES_KEY_LEN)
            self.keyDict[thisDay] = newDailyAESKey

        dailyAESKey = self.keyDict[thisDay] = newDailyAESKey
        # print dailyAESKey
        # print len(dailyAESKey)

        # Encryption of Logtext
        encryption_suite = AES.new(dailyAESKey, AES.MODE_CBC, AES_IV)
        remainder = (len(logText) % 16)
        text = logText + (16 - remainder) * " "
        cipher_text = encryption_suite.encrypt(text)
        # print "CipherText: " + cipher_text

        logtime = str(datetime.datetime.now().hour) + str(datetime.datetime.now().minute) + str(
            datetime.datetime.now().second) + str(datetime.datetime.now().microsecond)

        f = open("Log/" + thisDay + logtime + '.txt', 'wb')
        f.write(str(cipher_text))  # write ciphertext to file
        f.close()

        # Encrypt daily AES Key
        encryptedDailyAESKey = recoveredPubKey.encrypt(dailyAESKey, 32)
        print encryptedDailyAESKey

        # Post encrypted daily AES Key back to KeyServer
        payload = {'key': encryptedDailyAESKey}
        #r = requests.post(KEY_SERVER, data=payload)
        print "Sent AES Key to KeyServer: " + r.reason

        target = open("tmp.txt", 'w')
        target.write(str(encryptedDailyAESKey))
        target.close()
        files = {'upload_file': open('tmp.txt', 'rb')}

        r = requests.post(KEY_SERVER, files=files)
        os.remove("tmp.txt")
        print "File sent"
