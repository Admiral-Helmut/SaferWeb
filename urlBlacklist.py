import glob



def check_url(url):

    for filename in glob.iglob('blacklists/**/domains'):
        with open(filename, 'r') as infile:
            data = infile.read()
            my_list = data.splitlines()
            for line in my_list:
                if line in url and len(line) > 1:
                    print 'Blacklisted domain detected : ' + line
                    return True

    return False


print check_url('http://panty-paradise.com/test.php')