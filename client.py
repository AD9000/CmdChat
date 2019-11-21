import socket
import sys
import signal
import time
import threading
import Intents
import select
from CaseInsensitiveDict import CaseInsensitiveDict
from collections import defaultdict


class Client():
    def __init__(self, serverIP, serverPort):
        self.serverIP = serverIP
        self.serverPort = serverPort

        self.isLoggedIn = False

        # Socket
        self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Signal handler
        signal.signal(signal.SIGINT, self.signal_handler)

        self.lock = threading.Condition()
        self.pLock = threading.Condition()
        self.welcSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.welcSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.welcSocket.bind(('', 0))
        self.welcSocket.listen(10)

        self.welcPort = self.welcSocket.getsockname()[1]
        self.welcIp = socket.gethostbyname(socket.gethostname())
        self.name = ''

        self.validpeers = []

        self.p2p = defaultdict(lambda: None, {})
        self.supportedCommands = CaseInsensitiveDict({Intents.MESSAGE: self.publicMessage, Intents.BROADCAST: self.broadcast,
                                                      Intents.WHOELSE: self.whoelse, Intents.WHOELSESINCE: self.whoelsesince, Intents.BLOCK: self.blockUser, Intents.UNBLOCK: self.unblockUser, Intents.LOGOUT: self.logout,
                                                      Intents.STARTPRIVATE: self.sendStartPrivate, Intents.PRIVATE: self.safeSendPrivate,
                                                      Intents.STOPPRIVATE: self.stopprivate})

    def welcome(self):
        print("Welcome to CmdChat. Finally you get to talk to your friends through the best UI ever: The command line! *Fireworks in background*")

    def safeClose(self, connection):
        if (not connection):
            return
        if (connection.fileno() != -1):
            connection.close()

    def stopprivate(self, data):
        if (not data) or len(data) < 2:
            print('Usage: stopprivate <user>')
            return

        # user and connection
        print(data)
        user = data[1]
        check = True

        if (len(data) > 2):
            check = data[2]
            if (check is None):
                return

        with self.pLock:
            if (not user) or (user not in self.p2p):
                print('You had never connected with', user)
                return

            connection = self.p2p.get(user)

            print('Closed your private connection with', user)
            # tell the user
            if (check):
                try:
                    connection.send(user.encode())
                    time.sleep(0.2)
                    connection.send(Intents.STOPPRIVATE.encode())
                except:
                    pass

            # get the socket and close it
            self.safeClose(connection)

            # Remove from list
            self.p2p.pop(user)

    def startPrivate(self):
        user = self.clientSocket.recv(4096).decode()
        # accept data from the server and create new private connection
        data = self.clientSocket.recv(4096).decode()
        if (not data):
            print('Internal Server Error')

        ip, port = data.split()
        print('trying to connect to ', ip, port)

        try:
            newsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connect(newsock, ip, int(port), 1000)

            print('sending your username...', self.name, 'to', user)
            with self.pLock:
                self.p2p[user] = newsock
                self.safeSendData(self.name, self.p2p[user])

                # Allow messaging from the user
                p2pthread = threading.Thread(
                    target=self.handlePeer, args=[self.p2p.get(user)], daemon=True)
                p2pthread.start()

            print('You are now connected privately with ', user)

        except Exception as e:
            print('could not connect because ', e)

    def safeSendPrivate(self, data):
        print('safe send data called')
        if (not data) or len(data) < 3:
            print('Usage: private <user> <message>')
        user = data[1]
        message = ' '.join(data[2:])
        if (user not in self.p2p):
            print('To message user privately, connect to them first using startprivate')
            return

        try:
            print('sending message', message)
            if (self.safeSendData(self.name, self.p2p.get(user))):
                self.stopprivate([Intents.STOPPRIVATE, user, False])
            time.sleep(0.1)
            if (self.safeSendData(self.name + ' (Private): ' +
                                  message, self.p2p.get(user))):
                self.stopprivate([Intents.STOPPRIVATE, user, False])
        except Exception as e:
            print('Could not send data because', e)

    # def safelySendPrivateData(self, connection, message):
    #     if (not connection):
    #         connection = self.clientSocket
    #     try:
    #         connection.send(message.encode())
    #     except socket.error:
    #         self.unexpectedClose()
    #         return True
    #     except IOError:
    #         self.unexpectedClose()
    #         return True

    def sendStartPrivate(self, data):
        print('in start private....', data)
        if (not data) or len(data) < 2:
            print('Usage: startprivate <user>')
            return

        print('startprivate called from client')

        # Send intent to start private
        self.safeSendAll([Intents.STARTPRIVATE, data[1],
                          Intents.END_OF_COMMS], 0.1)

    def login(self):
        print('connecting...')
        self.connectToServer(50)
        print('connected...')

        # Prime the server by sending an intent to it
        if (self.safeSendData(Intents.LOGIN_USER)):
            print('Server cannot be reached')
            self.endClient(0)

        print('sent data')

        # Get the username and password and try to login
        while (True):
            print("Enter your username")
            username = input('$ ')
            print("Enter your password")
            password = input('$ ')
            message = username + " " + password

            # Try to log the user in:
            response = self.sendDataToServer(message)
            if (response.decode() == Intents.AUTH_SUCCESS):
                print(response.decode())
                break
            else:
                if (response):
                    print(response.decode(), '\n')
                else:
                    print('You have been automatically timed out due to inactivity')
                    self.endClient(1)

        self.onConnected()

    def handleP2PMessaging(self):
        p2pThread = None
        self.welcSocket.listen(10)
        while(True):
            connection = None
            addr = None
            print('accepting...')
            connection, addr = self.welcSocket.accept()
            print('accepted', connection, addr)

            p2pThread = threading.Thread(target=self.handlePeer, args=[
                                         connection])
            p2pThread.daemon = True
            p2pThread.start()

    def getValidPeers(self):
        self.safeSendAll([Intents.GETVALIDPEERS, Intents.END_OF_COMMS], 0.2)

        data = self.safeReceiveData()
        while (data != Intents.END_OF_COMMS):
            with self.lock:
                self.validpeers.append(data)
            data = self.safeReceiveData()

    def handlePeer(self, connection):
        # add the user to the p2p list
        user = self.safeReceiveData(connection)
        if (not user):
            self.safeClose(connection)
            self.endClient(0)

        if (user == Intents.STOPPRIVATE):
            print('shutting down private sess')
            with self.pLock:
                self.p2p.pop(user)
            self.safeClose(connection)
            self.endClient(0)
        print('handling peer...', user)

        with self.pLock:
            print('valid peers are:', self.validpeers)
            if (user not in self.p2p) and (user in self.validpeers):
                self.p2p[user] = connection
                print('Started private messaging session with', user)

        print(self.p2p)

        # talk to the peer
        while (True):
            data = None
            try:
                data = connection.recv(4096).decode()
                print('data received:', data)
            except (socket.error, IOError):
                self.safeClose(connection)
                self.endClient(0)
            except:
                pass

            if (not data) or (data and (data == Intents.STOPPRIVATE)):
                # print('shutting down private sess')
                if (data and (data == Intents.STOPPRIVATE)):
                    print('Shutting down private session with', user)
                with self.pLock:
                    if (user in self.p2p):
                        self.p2p.pop(user)
                self.safeClose(connection)
                self.endClient(0)

            print(data)

    def onConnected(self):
        # send p2p info
        self.safeSendData(str(self.welcIp) + ' ' + str(self.welcPort))
        self.name = self.safeReceiveData()

        # logged in
        self.isLoggedIn = True

        # get list of peers
        self.getValidPeers()

        # Thread to receive data
        recv_thread = threading.Thread(target=self.handleCommands)
        recv_thread.daemon = True
        recv_thread.start()

        # p2p thread
        p2p_thread = threading.Thread(target=self.handleP2PMessaging)
        p2p_thread.daemon = True
        p2p_thread.start()

        self.bgReceiveData()

    def displayWhoelse(self, data):
        for person in data:
            print('>> ' + person)

    def bgReceiveData(self):
        while (True):
            try:
                message = self.clientSocket.recv(8192)

                # If the response
                if (message.decode() == Intents.ACTIVITY_CHECK):
                    self.safeSendData(Intents.ACTIVE)
                elif (message.decode() == Intents.PEERSTARTPRIVATE):
                    self.recvPrivate()
                elif (message.decode() == Intents.WHOELSE or message.decode() == Intents.WHOELSESINCE):
                    data = []
                    packet = self.clientSocket.recv(8192).decode()
                    while (packet != Intents.END_OF_COMMS):
                        data.append(packet)
                        packet = self.clientSocket.recv(8192).decode()
                    self.displayWhoelse(data)
                elif (message.decode() == Intents.STARTPRIVATE):
                    self.startPrivate()
                elif (message.decode() == Intents.LOGOUT):
                    self.endClient(0)
                elif (message.decode() == Intents.END_OF_COMMS):
                    pass
                # elif (message.decode() == Intents.UNREAD_MESSAGES):
                #     reply = input(
                #         '\nWould you like to read your unread messages? (y/n)')
                #     if reply and (reply[0] == 'y' or reply[0] == 'Y'):
                #         self.safeSendData(Intents.YES)
                #         packet = self.clientSocket.recv(8192).decode()
                #         while (packet != Intents.END_OF_COMMS):
                #             print(packet)
                #             packet = self.clientSocket.recv(8192).decode()
                else:
                    # otherwise print the reponse out
                    print(message.decode() + '\n$ ', end='')

            except (socket.error, IOError):
                self.unexpectedClose()
                self.endClient(1)
                break
            except Exception as e:
                print('Exception while recieving data ---> ', e)
                break

    # def handleClose(self, connection):
    #     while (True):
    #         if (connection.fileno() == -1):
    #             print ('Server closed connection unexpectedly')
    #             self.endClient(1)
    #         time.sleep(1)
    #         print(connection.fileno())

    def unexpectedClose(self):
        print('The connection was closed unexpectedly')

    def safeSendData(self, message, connection=None):
        if (not connection):
            connection = self.clientSocket
        try:
            connection.send(message.encode())
        except (socket.error, IOError):
            self.unexpectedClose()
            return True

    def safeSendAll(self, messages, timeout):
        for message in messages:
            # Send the message. If there was an error, abort
            if (self.safeSendData(message)):
                return True
            time.sleep(timeout)

    def publicMessage(self, userInput):
        print(userInput)
        if (not userInput) or (len(userInput) < 2):
            return

        # Send a message request...

        user = userInput[1]
        message = ' '.join(userInput[2:])
        self.safeSendAll([Intents.MESSAGE, user, message,
                          Intents.END_OF_COMMS], 0.1)

    def handleCommands(self):
        while (True):
            try:
                inp = input()
                if (not inp):
                    continue

                inp = inp.strip().split()

                # Extract command and params
                command = inp[0]
                print('input ----> ', inp)

                if (command in self.supportedCommands):
                    self.supportedCommands[command](inp)
                    # time.sleep(0.1)
                else:
                    print('Command not supported:', inp[0])
            except KeyboardInterrupt:
                print('You interrupted!')
                break

    def checksocket(self):
        while True:
            try:
                ret = select.select([self.clientSocket], [], [], 5)

                print(ret)
                if (self.clientSocket in ret[0]):
                    print('was readable')
                    continue
                else:
                    print('nope')
                    self.endClient(1)
                    break
                print(ret)
            except Exception as e:
                print('Exception checking socket ---> ', e)
                break

    def safeReceiveData(self, connection=None):
        if (not connection):
            connection = self.clientSocket
        while (True):
            # self.clientSocket.settimeout(2)
            try:
                # print ('recieving data')
                message = connection.recv(2048)

                # logout if needed
                # if (message.decode() == Intents.LOGOUT):
                #     print (self.clientSocket.recv(2048).decode())
                #     self.logout()

                # otherwise print the reponse out
                return message.decode()

                # Reset timeout
                # self.clientSocket.settimeout(None)

                # time.sleep(1)
            # except socket.timeout:
            #     print ('timeout')
            #     continue
            except socket.error or IOError:
                self.unexpectedClose()
                self.endClient(1)
            except Exception as e:
                print('Exception while recieving data ---> ', e)
                break

    # def logout(self):
    #     print('Exiting...')
    #     self.endClient(0)

    def handleTimeout(self):
        pass

    def connect(self, sock, ip, port, timeoutT):
        sock.connect((ip, port))

    def connectToServer(self, timeoutT):
        self.clientSocket.connect((self.serverIP, self.serverPort))

    def sendDataToServer(self, message):
        # Send message to the server
        try:
            if self.clientSocket.fileno() != -1:
                self.clientSocket.send(message.encode())
                # wait for the reply from the server
                receivedMessage = self.clientSocket.recv(2048)
                return receivedMessage
        except socket.timeout:
            print('Connection timed out')
            self.clientSocket.close()
        except Exception as e:
            print(e)

    '''
    Send broadcast messages
    '''

    def broadcast(self, message):
        if (not message) or len(message) <= 1:
            print('Usage: broadcast <message>')
            return
        command = message[0]
        data = ' '.join(message[1:])
        self.safeSendAll([Intents.BROADCAST, data, Intents.END_OF_COMMS], 0.1)

    '''
    get list of people currently online
    '''

    def whoelse(self, data):
        # send a whoelse intent
        self.safeSendAll([Intents.WHOELSE, Intents.END_OF_COMMS], 0.1)

    '''
    get list of people that have been online for the past <time> seconds
    '''

    def whoelsesince(self, data):
        if (not data) or len(data) < 1:
            print('Usage: whoelsesince <time(seconds)>')
            return
        time = data[1]
        # send a whoelse intent
        self.safeSendAll([Intents.WHOELSESINCE, time,
                          Intents.END_OF_COMMS], 0.1)

    '''
    Block someone!
    '''

    def blockUser(self, data):
        if (not data) or len(data) < 1:
            print('Usage: block <user>')
            return

        user = data[1]

        # Send block intent
        self.safeSendAll([Intents.BLOCK, user, Intents.END_OF_COMMS], 0.1)

    '''
    Unblock someone who is blocked
    '''

    def unblockUser(self, data):
        if (not data) or len(data) < 1:
            print('Usage: unblock <user>')

        user = data[1]

        # Send unblock intent
        self.safeSendAll([Intents.UNBLOCK, user, Intents.END_OF_COMMS], 0.1)

    '''
    Logout
    '''

    def logout(self, data):
        # Send a logout intent
        self.safeSendAll([Intents.LOGOUT, Intents.END_OF_COMMS], 0.1)

    def signal_handler(self, sig, frame):
        for conn in self.p2p:
            self.safeClose(conn)
        self.endClient()

    def endClient(self, exitCode=0):
        # Close the socket
        if self.clientSocket.fileno() != -1:
            self.clientSocket.close()

        # done
        sys.exit(exitCode)


def getCmdArg(index):
    if (not sys.argv):
        return None
    if index < len(sys.argv) and sys.argv[index]:
        return sys.argv[index]


def usage():
    print('Usage: python3 client.py <Server Ip Address> <Server Port No>')
    sys.exit(0)


if __name__ == "__main__":
    serverIP = getCmdArg(1)
    serverPort = None
    if (getCmdArg(2)):
        serverPort = int(getCmdArg(2))

    if (not (serverPort and serverIP)):
        usage()

    client = Client(serverIP, serverPort)

    # Client is welcomed
    client.welcome()

    # Must login before using anything.
    if (client.login()):
        client.handleCommands()

    # print (client.sendDataToServer("lets see if this works..."))
    # time.sleep(3)
    # client.sendDataToServer("trying again...")
    # client.sendDataToServer("Again")
    # time.sleep(5)
    # client.sendDataToServer("Should not work")
    # time.sleep(12)
    # client.sendDataToServer("Should definitely not work")
    # client.welcome()
    # if (client.login()):
    #     client.handleRequests()
