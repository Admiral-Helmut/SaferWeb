import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import ast
import datetime

AES_IV = 'IV13579IV2468IV1'     # 128 Bit Initialisierungsvektor

#decrypted code below

f = open('/home/admiral-helmut/Projekte/SaferWeb/KeyServer/LogKeys/1612017.pem', 'r')
message = f.read()
print "AES Key:"
print message

encryptedKey = '\x14Y\'\xa0\xa7$n\x99I!\xc67J0I8\xac\xac\x01X\x81]:\xcc\xf3p\xcc\x02CJ\xb2\xf2\x18\xcbm\x04?S\xcc|\xf4\xf9"\xc2\x92\xa2E\xfe\x08\x19\x85\x14VAO\'\x10\x9e\xee\xe4\xfb\xa6\x96(\xa6\x11\xdb\xfa@a\x81l\xdc\x1f\xea1\xfd\x96\xb5\xe7f\xe8\x07+ \xbc\xae\xb60a\xda5\x8a\xc8\xd8\xc5\xa0[.\x93\xcd\xb5\xa4\x04\x84\x10\xd0\xc8\xacc\xb49~=pu\xa6\xdf \xfc\x86\x9b\xb9\xb099\xb8`\xf0\x89\x8f%\xf8\x00;d3t\x00\xfc;?\xb0\xdf\xadu\x18\x83+\xff\xb5\xbe\x1fH\x94\x1b\x08\xb6c!\xd0\xbd7D\xe5\x85\xfdU\x8e*LG\xc1&\xb1\xb6\xd6]%\xf9\x1d?\'\x95\xe3\xdd0*\x01\xc6!\xab\xb2\x05Y\x15 %\x89\xe2\x1e)\xe9\x89C\x06\xa3pR\xc7\x16R]\x1c#v\xe3&\x107\xbd\x8ah\xf4\xf2\xed\xbb\xb8B\x86@V\x19\xbe\x82\x87]"\xbe\x0b\xc1p5\xb1\x07d{\x1f\x8d\xbc\x84\xabZ\xabg\xa8'

f = open('/home/admiral-helmut/Projekte/SaferWeb/masterKey/privateMasterKey.pem','rb')
key = RSA.importKey(f.read())
decrypted = key.decrypt(str(encryptedKey))
#decrypted = key.decrypt(ast.literal_eval(str(message)))

print decrypted


 #Decryption AES
decryption_suite = AES.new(decrypted, AES.MODE_CBC, AES_IV)
f = open('/home/admiral-helmut/Projekte/SaferWeb/Log/161201721129248659.txt', 'r')
messageLog = f.read()
plain_text = decryption_suite.decrypt(messageLog)

print "LogMessage:"
print plain_text