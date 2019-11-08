import threading
import time
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
        
    def authorize(self, username, passw):
        # Checking if the user can be authorized
        with self.lock:
            # print ('got the lock!')
            if ((username in self.authdict.keys()) and (username not in self.blockedClients)):
                # print ('in the if')
                check = self.authdict[username] == passw
                if (not check):
                    # print ('check false')
                    # print (username)
                    # print (self.invalidCount)
                    if (self.invalidCount and self.invalidCount[username] and (self.invalidCount[username] + 1 == 3)):
                        # print ('blocking user')
                        self.invalidCount[username] = 0
                        blockT = threading.Thread(target=self.blockClient, args=[username])
                        blockT.daemon=True
                        blockT.start()
                        self.lock.notify()
                        return 'Too many invalid logins. You have been blocked for ' + str(self.blockDuration) + ' seconds.'
                    else:
                        print ('added to count')
                        if (self.invalidCount and self.invalidCount[username]):
                            self.invalidCount[username] += 1
                        else:
                            self.invalidCount[username] = 1
                        return "Invalid Password"
                        
                else:
                    print ('ok....')
                    loginT = threading.Thread(target=self.login, args=[username])
                    loginT.daemon=True
                    loginT.start()
                    return "Login Successful"

            elif username in self.blockedClients:
                return 'You have been blocked. Try again later'
            else:
                return 'Invalid Username'

    def login(self, user):
        with self.lock:
            self.clients.append(user)
            self.invalidCount[user] = 0
            self.lock.notify()
    
    def blockClient(self, client):
        if client not in self.authdict.keys():
            # print ('was never blocked oof \n\n\n\n')
            return False
        else:
            # print('blocking...')
            self.blocker(client)

    def blocker(self, client):
        # print ('the blocker was called..')
        with self.lock:
            self.blockedClients.append(client)
            # print ('this should have workedn\n\n\n\n\n', self.blockedClients)
            self.lock.notify()

        # Block client for the duration
        print(self.blockDuration)
        time.sleep(self.blockDuration)

        with self.lock:
            self.blockedClients.remove(client)
            self.lock.notify()
    
    def createAccount(self, username, passw):
        f = open('credentials.txt', 'a')
        f.write(username + ' ' + passw)