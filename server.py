import socket
import threading
import time
import datetime as dt
import signal
import sys
from Authorization import Authorization
import Intents
import Data
import select
import datetime
from CaseInsensitiveDict import CaseInsensitiveDict
import Messages
from collections import defaultdict


class Server():
    def __init__(self, serverPort=12000, blockDuration=10, timeout=1000):
        super().__init__()

        self.blockDuration = blockDuration
        self.timeout = timeout

        self.auth = Authorization(self.blockDuration)
        self.welcSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.welcSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.welcSocket.bind(('localhost', serverPort))
        self.lock = threading.Condition()

        # Signal handler
        signal.signal(signal.SIGINT, self.signal_handler)

        # Clients and their sockets
        clientlist = self.auth.loadClients()
        self.clients = dict(zip(clientlist, [defaultdict(
            lambda: None, {}) for i in range(len(clientlist))]))
        # for client in self.clients:
        #     self.initClient(client)
        print(self.clients)

        self.activeUsers = defaultdict(lambda: None, {})

        # Commands supported by the server
        self.supportedCommands = CaseInsensitiveDict({Intents.MESSAGE: self.publicMessage,
                                                      Intents.BROADCAST: self.userBroadcast, Intents.WHOELSE: self.whoelse,
                                                      Intents.WHOELSESINCE: self.whoelsesince, Intents.BLOCK: self.blockUser,
                                                      Intents.UNBLOCK: self.unblockUser, Intents.LOGOUT: self.userLogout,
                                                      Intents.STARTPRIVATE: self.startPrivate,
                                                      Intents.GETVALIDPEERS: self.getValidPeers})

    def getValidPeers(self, fromuser, data):
        with self.lock:
            if fromuser not in self.clients:
                return
            self.safeSendAllOrLogout(self.clients.get(fromuser).get(Data.CONNECTION), list(self.clients.keys()) + [Intents.END_OF_COMMS], 0.2)

    # def initClient(self, client):
    #     # Client needs a username
    #     client.get(Data.USERNAME] = None

    #     # Timeout
    #     client.get(Data.TIMEOUT] = None

    #     # logged in?
    #     client.get(Data.IS_LOGGED_IN] = False

    #     # Last login and logout times
    #     client.get(Data.LAST_LOGIN_TIME] = None
    #     client.get(Data.LAST_LOGOUT_TIME] = None

    #     # Socket
    #     client.get(Data.CONNECTION] = None

    #     # Blocked client list and unread messages list
    #     client.get(Data.BLOCKED_CLIENTS] = []
    #     client.get(Data.UNREAD_MESSAGES] = []

    def startPrivate(self, fromuser, data):
        print ('startprivate called')
        print (data, fromuser)
        if (not (data and fromuser)) or (fromuser not in self.clients) or len(data) < 1:
            return

        touser = data[0]
        connection = self.clients.get(fromuser).get(Data.CONNECTION)

        # invalid user
        print ('checking if user exists...')
        if (touser not in self.clients):
            self.safeSendDataOrLogout(connection, 'User not found!')
            return

        # self
        print ('checking if user is unique.....')
        if (fromuser == touser):
            self.safeSendDataOrLogout(connection, 'You already have private access to yourself!')
            return

        # offline
        print ('checking online...')
        if not (Data.IS_LOGGED_IN in self.clients.get(touser)) or (not self.clients.get(touser).get(Data.IS_LOGGED_IN)):
            self.safeSendDataOrLogout(connection, touser + ' is offline!')
            return
        
        # blocked
        print ('checking if blocked...')
        if self.clients.get(Data.BLOCKED_CLIENTS) and (fromuser in self.clients.get(Data.BLOCKED_CLIENTS)):
            self.safeSendDataOrLogout(connection, 'Cannot start private as ' + touser + ' has blocked you')
            return

        print('sending data...')
        # Send the ip address and port number
        self.safeSendAllOrLogout(connection, [Intents.STARTPRIVATE, touser, self.clients.get(touser).get(Data.PRIVATE_IP) + ' ' + self.clients.get(touser).get(Data.PRIVATE_PORT)], 0.1)


        
    def blockUser(self, fromuser, data):
        print('block called')
        if (not (data and fromuser)) or fromuser not in self.clients.keys():
            return

        connection = self.clients.get(fromuser).get(Data.CONNECTION)
        user = data[0]
        print(connection, user)
        with self.lock:
            # Invalid user to block
            if (user not in self.clients.keys()):
                self.safeSendDataOrLogout(connection, Messages.USER_NOT_FOUND)
                return

            # user was already blocked
            if (Data.BLOCKED_CLIENTS in self.clients.get(user)) and (user in self.clients.get(user).get(Data.BLOCKED_CLIENTS)):
                self.safeSendDataOrLogout(
                    connection, Messages.ALREADY_BLOCKED + ": " + user)
                return

            # block user
            self.clients.get(fromuser).get(Data.BLOCKED_CLIENTS).append(user)
            print('user has been blocked!')
            print(self.clients.get(fromuser).get(Data.BLOCKED_CLIENTS))

    def unblockUser(self, fromuser, data):
        if (not (data and fromuser)) or fromuser not in self.clients.keys():
            return

        connection = self.clients.get(fromuser).get(Data.CONNECTION)
        user = data[0]
        with self.lock:
            # Invalid user to unblock
            if (user not in self.clients.keys()):
                self.safeSendDataOrLogout(connection, Messages.USER_NOT_FOUND)
                return

            # user was never blocked
            if (user not in self.clients.get(fromuser).get(Data.BLOCKED_CLIENTS)):
                self.safeSendDataOrLogout(
                    connection, Messages.NEVER_BLOCKED + ": " + user)
                return

            # unblock user
            self.clients.get(fromuser).get(Data.BLOCKED_CLIENTS).remove(user)

            self.safeSendDataOrLogout(
                connection, 'User has been unblocked! : ' + user)
            print(self.clients.get(user).get(Data.BLOCKED_CLIENTS))

    def userLogout(self, fromuser, data):
        # print ('\n\nuser wants to logout...\n\n',  fromuser)
        if (not fromuser) or fromuser not in self.clients.keys():
            return

        self.logout(self.clients.get(fromuser).get(Data.CONNECTION),
                    fromuser, 'You have successfully been logged out')

    def whoelse(self, fromuser, data):
        print('whoelse was called', data)
        online = []
        with self.lock:
            for user in self.clients.keys():
                if (user == fromuser):
                    continue
                if (Data.IS_LOGGED_IN in self.clients.get(user)) and (self.clients.get(user).get(Data.IS_LOGGED_IN)):
                    online.append(user)
        print('whoelse online? ', online)
        # Send intent to user
        self.safeSendAllOrLogout(self.clients.get(fromuser).get(Data.CONNECTION), [
                                 Intents.WHOELSE] + online + [Intents.END_OF_COMMS], 0.1)

    def whoelsesince(self, fromuser, data):
        if (not data) or len(data) < 1:
            return
        elapsed = float(data[0])
        whoelse = []
        with self.lock:
            for user in self.clients.keys():
                if (user == fromuser):
                    continue
                if (Data.IS_LOGGED_IN in self.clients.get(user)) and (self.clients.get(user).get(Data.IS_LOGGED_IN)):
                    whoelse.append(user)
                elif (Data.LAST_LOGOUT_TIME in self.clients.get(user)) and ((datetime.datetime.now() - self.clients.get(user).get(Data.LAST_LOGOUT_TIME)).total_seconds() <= elapsed):
                    whoelse.append(user)

        # Send intent to user
        self.safeSendAllOrLogout(self.clients.get(fromuser).get(Data.CONNECTION), [
                                 Intents.WHOELSESINCE] + whoelse + [Intents.END_OF_COMMS], 0.1)

    def safeSendAllOrLogout(self, connection, messages, timeout):
        for message in messages:
            # Send the message. If there was an error, abort
            if (self.safeSendDataOrLogout(connection, message)):
                return True
            time.sleep(timeout)

    def userBroadcast(self, fromuser, message):
        print(message)
        data = message.pop(0)
        with self.lock:
            for user in self.clients.keys():
                if (user == fromuser):
                    continue
                if (Data.IS_LOGGED_IN in self.clients.get(user)) and (self.clients.get(user).get(Data.IS_LOGGED_IN)):
                    self.publicMessage(
                        fromuser, [user, 'Broadcast: ' + data], False)

    def authorizeMessage(self, fromuser, touser):
        with self.lock:
            # print ('dict of fromuserr ---->', self.clients.get(fromuser))
            # print ('keys of dict ', self.clients.get(fromuser).keys())
            # print ('key in? ', Data.BLOCKED_CLIENTS in self.clients.get(fromuser).keys())
            # print ('is to user in? ', touser in self.clients.get(fromuser).get(Data.BLOCKED_CLIENTS))
            # print ('looking for ', touser)
            # print ('fromusers blocked client', self.clients.get(fromuser).get(Data.BLOCKED_CLIENTS))
            if (Data.BLOCKED_CLIENTS in self.clients.get(touser).keys()) and (fromuser in self.clients.get(touser).get(Data.BLOCKED_CLIENTS)):
                # print ('does it have the field? ', Data.BLOCKED_CLIENTS in self.clients.get(fromuser).keys())
                print(self.clients.get(touser).get(Data.BLOCKED_CLIENTS))
                return False
            print('user ------------> ', touser)
            print(self.clients.get(touser).get(Data.BLOCKED_CLIENTS))
            return True

    def publicMessage(self, fromuser, data, storeMessage=True):
        try:
            touser, message = data
            print(touser, message)
        except:
            self.safeSendDataOrLogout(self.clients.get(fromuser).get(
                Data.CONNECTION), Intents.INVALID_COMMAND)
            return
        # Find the user:
        with self.lock:
            connection = self.clients.get(fromuser).get(Data.CONNECTION)
            # Invalid user sending a message...
            if not (fromuser in self.clients.keys()):
                return

            # no such user to send data to
            if not (touser in self.clients.keys()):
                self.safeSendDataOrLogout(connection, Messages.USER_NOT_FOUND)
                return

            # user trying to send message to himself
            if (fromuser == touser):
                self.safeSendDataOrLogout(
                    connection, Messages.RECIEVER_EQUALS_SENDER)
                return

            # sender is blocked by receiver
            # print (self.clients.get('hans').get(Data.BLOCKED_CLIENTS))
            if (not self.authorizeMessage(fromuser, touser)):
                print('')
                self.safeSendDataOrLogout(
                    connection, Messages.RECIEVER_BLOCKED_SENDER + ' by ' + touser)
                return

            # if the user is not online, store the message instead (if thats what is asked...)
            if (not self.clients.get(touser).get(Data.IS_LOGGED_IN)):
                if (not storeMessage):
                    return
                if not self.clients.get(touser).get(Data.UNREAD_MESSAGES):
                    self.clients[touser][Data.UNREAD_MESSAGES] = []
                self.clients.get(touser).get(Data.UNREAD_MESSAGES).append(
                    ' >> ' + fromuser + ": " + message)
                self.safeSendDataOrLogout(self.clients.get(fromuser).get(Data.CONNECTION), (
                    ' >> ' + touser + " is not online at the moment. They can look at your message when they come online"))
            # send the message!
            else:
                print('sending the message from ', fromuser, 'to', touser,
                      'using connection', self.clients.get(touser).get(Data.CONNECTION))
                self.safeSendDataOrLogout(self.clients.get(touser).get(
                    Data.CONNECTION), (' >> ' + fromuser + ": " + message))

    # def getCmdArg(self, args, argToFind):
    #     for arg in range(len(args)):
    #         if args[arg] == argToFind:
    #             return args[arg + 1]

    def signal_handler(self, sig, frame):
        print("\nShutting down server...")
        self.welcSocket.close()
        sys.exit(0)

    def signup(self, username, passw):
        self.auth.createAccount(username, passw)

    def initp2p(self, username, connection):
        # Wait for user to send data about its welcsocket and port
        privatedata = self.safeReceiveData(connection)

        print(privatedata)
        # parse and validate the private data
        while (not privatedata) or len(privatedata.split()) < 2:
            self.safeSendDataOrLogout(connection, Intents.WRONGPRIVATEDETAILS)

        # otherwise add it
        ip, port = privatedata.split()
        print('active users------------------> ', self.activeUsers)
        self.addData(username, Data.PRIVATE_IP, ip)
        self.addData(username, Data.PRIVATE_PORT, port)

    def login(self, connection):
        # receive data in a loop
        while (True):
            try:
                # Get the login details from the client
                print('starting again...')
                loginDetails = self.receiveData(connection)
                details = [x.strip() for x in loginDetails.split()]
                if (not (details and len(details) == 2)):
                    self.sendData(connection, Intents.LOGIN_REJECT)
                    time.sleep(0.1)
                    continue
                username, passw = details

                # Authorize the client. If it works, send the response back
                response = self.auth.authorize(username, passw)
                print('Auth response: ------> ', response)

                print(loginDetails)
                print(username, passw)

                if (not response):
                    self.sendData('Internal Server Error')
                else:
                    print('sending the response back to the clients')
                    print(response)
                    connection.send(response.encode())
                    print('response sent')

                    if (response == Intents.AUTH_SUCCESS):
                        time.sleep(0.1)
                        self.initp2p(username, connection)
                        time.sleep(0.1)
                        self.safeSendDataOrLogout(connection, username)
                        time.sleep(0.1)
                        print('yes indeed')
                        self.addClient(connection, username)
                        print('starting timeout thread...')
                        # Begin thread to timeout the user after the
                        # required number of seconds
                        self.startThread(self.userTimeout, True, [username])
                        return username

            except socket.timeout:
                print('Internal Server Error: Timeout')
                break
            except Exception as e:
                print('exception during client login-----> ', loginDetails)
                print('being..', e)
                # print (username, passw)
                if (not self.checksocket(connection)):
                    self.unexpectedClientClosure()
                    self.logout(connection)
                else:
                    print('Invalid format!')
                break

    def checksocket(self, connection):
        try:
            connection.settimeout(2)
            self.sendData(connection, Intents.ACTIVITY_CHECK)
            message = self.receiveData(connection)
            connection.settimeout(None)

            if (message.decode() == Intents.ACTIVE):
                return True
            return False
        except (socket.timeout, IOError):
            return False
        except Exception as e:
            print('Exception while checking socket data ---> ', e)
            return False

    def broadcast(self, message):
        print(message)
        if (not message):
            return

        with self.lock:
            print(self.clients.values())
            for client in self.clients.values():
                try:
                    print(client)
                    if (not ((Data.IS_LOGGED_IN in client.keys()) and client.get(Data.IS_LOGGED_IN))):
                        continue
                    client.get(Data.CONNECTION).send(message.encode())
                    print('broadcast sent')
                except socket.timeout:
                    self.logout(client.get(Data.CONNECTION),
                                client.get(Data.USERNAME))
                    break
                except Exception as e:
                    print('exception while broadcasting ----> ' + str(e))
                    break

    def startThread(self, targetFunc, daemon, arguments):
        # Create new thread.
        newthread = threading.Thread(target=targetFunc, args=arguments)
        newthread.daemon = daemon
        newthread.start()
        return newthread

    def addClient(self, connection, username):
        # Assuming that the client is not logged in yet
        # send broadCast
        self.broadcast(username + ' has joined.')
        with self.lock:
            #     print ('got lock')
            if username not in self.clients:
                self.clients[username] = defaultdict(lambda: None, {})

            # init a blocked clients list if that does not exists
            if not Data.BLOCKED_CLIENTS in self.clients.get(username):
                self.clients[username][Data.BLOCKED_CLIENTS] = []

            # for unread messages
            if (not Data.UNREAD_MESSAGES in self.clients.get(username).keys()):
                self.clients[username][Data.UNREAD_MESSAGES] = []

            self.activeUsers[connection] = username

        # Store the username
        self.addData(username, Data.USERNAME, username)

        # Store the connection socket
        self.addData(username, Data.CONNECTION, connection)

        # set the isloggedin flag
        self.addData(username, Data.IS_LOGGED_IN, True)

        # store/update the last login time
        self.addData(username, Data.LAST_LOGIN_TIME, datetime.datetime.now())

        # init a timeout for logging the user out
        self.addData(username, Data.TIMEOUT, int(self.timeout))

        print('done adding data')

    def addData(self, username, tag, data):
        with self.lock:
            if (username in self.clients):
                self.clients[username][tag] = data

    def resetTimeout(self, username):
        with self.lock:
            if (self.clients and self.clients.get(username)):
                self.clients[username][Data.TIMEOUT] = self.timeout

    def logout(self, connection, username=None, additionalMessage=None):
        # Remove from active connections
        with self.lock:
            self.activeUsers.pop(connection, None)

        if ((not username) or (username not in self.clients.keys()) or (not self.clients.get(username).get(Data.IS_LOGGED_IN))):
            return

        # connection = self.clients.get(username).get(Data.CONNECTION]

        print('logging user out ', self.clients.get(username))
        self.auth.logout(username)
        self.clients[username][Data.IS_LOGGED_IN] = False
        self.clients[username][Data.LAST_LOGOUT_TIME] = datetime.datetime.now()

        if (additionalMessage):
            if (not self.safeSendData(connection, additionalMessage)):
                self.endSession(0, connection)
            time.sleep(0.1)

        # Send the user logout message
        self.safeSendData(connection, Intents.LOGOUT)

        print(self.clients.get(username))

        # end the current thread
        self.endSession(0, connection)

    def sendData(self, connection, message):
        print('sending data -----> ', message)
        connection.send(message.encode())

    def unexpectedClientClosure(self):
        print('Unexpected client closure')

        # No need to continue session if client closed
        # self.endSession(0, connection)

    def cleanup(self, connection):
        self.logout(connection, self.activeUsers[connection])
        self.endSession(0, connection)

    def safeSendData(self, connection, message):
        try:
            connection.send(message.encode())
            return True
        except (socket.error, IOError):
            self.unexpectedClientClosure()
            return False

    def receiveData(self, clientSocket):
        return clientSocket.recv(4096).decode()

    def safeReceiveData(self, connection):
        try:
            data = connection.recv(8192).decode()
            return data
        except (socket.error, IOError) as e:
            print('io error when receiving data --> ', e)
            self.unexpectedClientClosure()
            return False

    def isClosed(self, connection):
        return connection.fileno == -1

    '''
    Log the client out if he/she does not issue a command in self.timeout seconds
    '''

    def userTimeout(self, username):
        # Decrement inside loop
        while True:
            # print ('waiting...', username)
            # Wait for 1 second
            time.sleep(1)

            # Check if user timed out
            with self.lock:
                if (username in self.clients):
                    if (self.clients.get(username).get(Data.TIMEOUT)):
                        self.clients[username][Data.TIMEOUT] -= 1
                        if self.clients[username][Data.TIMEOUT] == 0:
                            self.logout(self.clients.get(username).get(
                                Data.CONNECTION), username, '\n\nYou have been automatically logged out due to inactivity')
                            break
                    else:
                        # Client does not have a timeout. Log him out!
                        self.logout(self.clients.get(username).get(
                            Data.CONNECTION), username)
                        break

        # Do nothing if the client is not logged in

    '''
    Return the list of users who are currently online:
    '''

    def usersCurrentlyOnline(self):
        if (self.clients):
            with self.lock:
                return [self.clients.get(user).get(Data.CONNECTION) for user in self.clients.keys]
        return []

    '''
    History: Provides the list of all users online within the given time (in seconds)
    '''

    def userOnlineHistory(self, time):
        users = []
        with self.lock:
            for conn in self.clients.values():
                # if the user is logged in, add him
                if conn.get(Data.IS_LOGGED_IN):
                    users.append(conn.get(Data.USERNAME))
                else:
                    if conn.get(Data.LAST_LOGOUT_TIME) > datetime.datetime.now() - datetime.timedelta(seconds=time):
                        users.append(conn.get(Data.USERNAME))

    '''
    Message Forwarding: Server receives a message from a client and then forwards it over to the recipient
    '''

    def messageForwarding(self):
        # TODO: To be implemented
        pass

    '''
    Ends the current session with the client. Closes the socket which may be open
    Note: The server can still accept new clients after this operation
    '''

    def endSession(self, exitCode=0, connection=None):
        if (connection and connection.fileno() != -1):
            connection.close()
        sys.exit(exitCode)

    '''
    Display all the unread messages
    '''

    def displayUnreadMessages(self, connection, username):
        unreadMessages = None
        with self.lock:
            unreadMessages = self.clients.get(
                username).get(Data.UNREAD_MESSAGES)

        if unreadMessages and len(unreadMessages) > 0:
            self.safeSendAllOrLogout(connection, [Messages.UNREAD_MESSAGES_START] + unreadMessages + [
                                     Messages.UNREAD_MESSAGES_END, Intents.END_OF_COMMS], 0.1)
            with self.lock:
                # empty the unread messages list
                self.clients.get(username)[Data.UNREAD_MESSAGES] = []

    '''
    Handles an incoming connection
    '''

    def handleConnection(self, connection, addr):
        # Connected to a client. Client then sends its intent. Server moves to handle this intent.
        # Get the intent
        intent = self.receiveData(connection)
        check = False
        username = None

        # If intent is to login, then log the user in
        if (intent == Intents.LOGIN_USER):
            connection.settimeout(self.timeout)
            username = self.login(connection)
            connection.settimeout(None)
            if not username:
                # End session immediately
                self.endSession(connection=connection)

            print(self.clients.get(username).get(Data.PRIVATE_IP), self.clients.get(username).get(Data.PRIVATE_PORT))

            # Tell the client the login is accepted. If that does not work, then log the user out
            # elif (not self.safeSendData(connection, Intents.LOGIN_ACCEPT)):
            #     self.logout(self.clients.get(username))
        else:
            # User cannot do anything else before logging in.
            if (not self.safeSendData(connection, Intents.LOGIN_REJECT)):
                self.logout(connection, username)

        # The fact that there is a username means that login was successful
        if (not username):
            self.endSession(0, connection)

        # See if the user wants to see unread messages
        self.displayUnreadMessages(connection, username)

        # At this point the user is logged in. Now to handle any other commands that the user issues.
        # Dont worry about the timeout. Thats what the usertimeout is for
        while (True):
            print('looping...')
            command = self.safeReceiveData(connection)
            # command = 'something'
            # If command does not exist or is False (there was an error) log user out
            # if (not command):
            #     # log the user out
            #     self.logout(username)

            # Check if the command is supported
            print('the command/intent is ', command)
            if ((not command) or command not in self.supportedCommands):
                self.safeSendDataOrLogout(connection, Intents.INVALID_COMMAND)
            else:
                # Recieve all the data client wants to send
                inp = []
                data = self.safeReceiveData(connection)
                while not (data == Intents.END_OF_COMMS):
                    inp.append(data)
                    data = self.safeReceiveData(connection)

                print('calling ', self.supportedCommands[command])
                # send data to the required function
                self.supportedCommands[command](username, inp)

    def safeSendDataOrLogout(self, connection, message, additionalMessage=None):
        if (not self.safeSendData(connection, message)):
            self.logout(
                connection, self.activeUsers[connection], additionalMessage)

    def recvConnection(self):
        # Listen for incoming connections
        self.welcSocket.listen()

        while(True):
            print('Waiting for connections...')
            connection, addr = self.welcSocket.accept()

            # Create new thread to handle the connection...
            recv_thread = threading.Thread(
                target=self.handleConnection, args=[connection, addr])
            recv_thread.daemon = True
            recv_thread.start()

def getCmdArg(index):
    if index < len(sys.argv) and sys.argv[index]:
        return int(sys.argv[index])


def usage():
    print('Usage: python3 server.py <Port Number> <Block Duration> <Timeout>')
    sys.exit(0)


if __name__ == "__main__":
    # print(datetime.datetime.now() - datetime.timedelta(minutes=10))
    serverPort = getCmdArg(1)
    blockDuration = getCmdArg(2)
    timeout = getCmdArg(3)

    if (not (serverPort or blockDuration or timeout)):
        usage()

    server = Server(serverPort, blockDuration, timeout)
    server.recvConnection()
