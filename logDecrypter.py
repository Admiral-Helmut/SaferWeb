import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import ast
import datetime

#decrypted code below

f = open('/home/admiral/Projekte/SaferWeb/SaferWeb/1511201634621285572.txt', 'r')
message = f.read()

f = open('/home/admiral/Projekte/SaferWeb/SaferWeb/15112016.pem','rb')
key2 = RSA.importKey(f.read())
decrypted = key2.decrypt(ast.literal_eval(str(message)))

print 'decrypted', decrypted


# Decryption AES
#decryption_suite = AES.new(key, AES.MODE_CBC, AES_IV)
#plain_text = decryption_suite.decrypt(cipher_text)

#print plain_text