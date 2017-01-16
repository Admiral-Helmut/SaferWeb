import glob



def check_url(url):

    for filename in glob.iglob('url_blacklists/**/domains'):
        with open(filename, 'r') as infile:
            data = infile.read()
            my_list = data.splitlines()
            for line in my_list:
                if line in url and len(line) > 1:
                    print 'Blacklisted domain detected : ' + line
                    return True

    return False

# this is for test purposes
#print check_url('https://panty-paradise.com/login.php')
