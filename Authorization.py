import threading
import time
import Intents

'''
Auth the user using the credentials.txt file
'''


class Authorization():
    def __init__(self, blockDuration):
        self.blockDuration = int(blockDuration)
        self.authdict = {}
        f = open('credentials.txt', 'r')
        for line in f:
            user, passw = line.split()
            self.authdict[user] = passw
        self.clients = []
        self.blockedClients = []
        self.lock = threading.Condition()
        self.invalidCount = dict([])

    '''
    Authorize user login
    '''

    def authorize(self, username, passw):
        # Checking if the user can be authorized
        with self.lock:
            if ((username in self.authdict.keys()) and (username not in self.blockedClients)):
                check = self.authdict[username] == passw
                if (not check):
                    if (self.invalidCount and (username in self.invalidCount.keys()) and (self.invalidCount[username] + 1 == 3)):
                        self.invalidCount[username] = 0
                        blockT = threading.Thread(
                            target=self.blockClient, args=[username])
                        blockT.daemon = True
                        blockT.start()
                        self.lock.notify()
                        return 'Too many invalid logins. You have been blocked for ' + str(self.blockDuration) + ' seconds.'
                    else:
                        if (self.invalidCount and (username in self.invalidCount)):
                            self.invalidCount[username] += 1
                        else:
                            self.invalidCount[username] = 1
                        return "Invalid Password"

                else:
                    if username in self.clients:
                        return 'A user with that username has already logged in.'
                    else:
                        loginT = threading.Thread(
                            target=self.login, args=[username])
                        loginT.daemon = True
                        loginT.start()
                        return Intents.AUTH_SUCCESS
            elif username in self.blockedClients:
                return 'You have been blocked. Try again later'
            else:
                return 'Invalid Username'

    '''
    Log the user in
    '''

    def login(self, user):
        with self.lock:
            self.clients.append(user)
            self.invalidCount[user] = 0
            self.lock.notify()

    '''
    Log the user out
    '''

    def logout(self, user):
        with self.lock:
            if (user not in self.clients):
                return
            self.clients.remove(user)
            self.lock.notify()

    '''
    block a client
    '''

    def blockClient(self, client):
        if client not in self.authdict.keys():
            return False
        else:
            self.blocker(client)

    '''
    block a client for a duration
    '''

    def blocker(self, client):
        with self.lock:
            self.blockedClients.append(client)
            self.lock.notify()

        # Block client for the duration
        time.sleep(self.blockDuration)

        with self.lock:
            self.blockedClients.remove(client)
            self.lock.notify()

    '''
    Load all clients from credentials.txt
    '''

    def loadClients(self):
        clientlist = []
        f = open('credentials.txt', 'r')
        for line in f:
            username = line.split().pop(0)
            clientlist.append(username)
        return clientlist
