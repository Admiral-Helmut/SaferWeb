import glob
import re


def check_cipher(cipher):

    for filename in glob.iglob('cipher_whitelists/ciphers'):
        with open(filename, 'r') as infile:
            data = infile.read()
            my_list = data.splitlines()
            for line in my_list:
                if line in cipher and len(line) > 1:
                    print 'Cipher suite OK : ' + line
                    return True

    return False