import socket
class Authorization():
    def __init__(self):
        self.authdict = {}
        f = open('credentials.txt', 'r')
        for line in f:
            user, passw = line.split()
            self.authdict[user] = passw

    def authorize(self, username, password):
        if username in authdict.keys():
            return authdict[username] == password

    def createAccount(self, username, passw):
        f = open('credentials.txt', 'a')
        f.write(username + ' ' + passw)

class System():
    def __init__(self):
        super().__init__()
        self.auth = Authorization()
        self.welcSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def signup(self, username, passw):
        self.auth.createAccount(username, passw)

if __name__ == "__main__":
    sys = System()
    sys.signup("hi", "howru")
