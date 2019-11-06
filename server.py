import socket
class Authorization():
    authdict = {}
    def loadAuth(self):
        f = open('credentials.txt', 'r')
        for line in f:
            user, passw = line.split()
            authdict[user] = passw

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