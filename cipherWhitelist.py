import glob

def check_cipher(cipher):

    for filename in glob.iglob('ciphers/whitelist'):
        with open(filename, 'r') as infile:
            data = infile.read()
            my_list = data.splitlines()
            for line in my_list:
                if line in cipher and len(line) > 1:
                    print 'Cipher suite OK : ' + line
                    return True

    return False

def blacklist_cipher(cipher):

    for filename in glob.iglob('ciphers/blacklist'):
        with open(filename, 'r') as infile:
            data = infile.read()
            my_list = data.splitlines()
            for line in my_list:
                if line in cipher and len(line) > 1:
                    print 'Cipher unsave : ' + line
                    return True

    return False