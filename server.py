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

    def startPrivate(self, fromuser, data):
        
        
        if (not (data and fromuser)) or (fromuser not in self.clients) or len(data) < 1:
            return

        touser = data[0]
        connection = self.clients.get(fromuser).get(Data.CONNECTION)

        # invalid user
        
        if (touser not in self.clients):
            self.safeSendDataOrLogout(connection, 'User not found!')
            return

        # self
        
        if (fromuser == touser):
            self.safeSendDataOrLogout(connection, 'You already have private access to yourself!')
            return

        # offline
        
        if not (Data.IS_LOGGED_IN in self.clients.get(touser)) or (not self.clients.get(touser).get(Data.IS_LOGGED_IN)):
            self.safeSendDataOrLogout(connection, touser + ' is offline!')
            return
        
        # blocked
        
        if self.clients.get(Data.BLOCKED_CLIENTS) and (fromuser in self.clients.get(Data.BLOCKED_CLIENTS)):
            self.safeSendDataOrLogout(connection, 'Cannot start private as ' + touser + ' has blocked you')
            return

        
        # Send the ip address and port number
        self.safeSendAllOrLogout(connection, [Intents.STARTPRIVATE, touser, self.clients.get(touser).get(Data.PRIVATE_IP) + ' ' + self.clients.get(touser).get(Data.PRIVATE_PORT)], 0.1)


        
    def blockUser(self, fromuser, data):
        # error check
        if (not (data and fromuser)) or fromuser not in self.clients.keys():
            return

        # get connection and user name
        connection = self.clients.get(fromuser).get(Data.CONNECTION)
        user = data[0]
        
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

            # send confirmation
            self.safeSendDataOrLogout(connection, user + ' has been blocked successfully')
            
            
    '''
    unblock some blocked user
    '''
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
            
    
    '''
    Log user out
    '''
    def userLogout(self, fromuser, data):
        # error check
        if (not fromuser) or fromuser not in self.clients.keys():
            return

        # logout and send permissions
        self.logout(self.clients.get(fromuser).get(Data.CONNECTION),
                    fromuser, 'You have successfully been logged out')

    '''
    Check who else is online
    '''
    def whoelse(self, fromuser, data):
        
        online = []
        with self.lock:
            # check each client
            for user in self.clients.keys():
                if (user == fromuser):
                    continue
                if (Data.IS_LOGGED_IN in self.clients.get(user)) and (self.clients.get(user).get(Data.IS_LOGGED_IN)):
                    online.append(user)
        
        # Send intent to user
        self.safeSendAllOrLogout(self.clients.get(fromuser).get(Data.CONNECTION), [
                                 Intents.WHOELSE] + online + [Intents.END_OF_COMMS], 0.1)

    '''
    Check whoelse has been online in a specific period of time
    '''
    def whoelsesince(self, fromuser, data):
        # error check
        if (not data) or len(data) < 1:
            return

        # get elaped time
        elapsed = float(data[0])
        whoelse = []
        with self.lock:
            # check each client
            for user in self.clients.keys():
                if (user == fromuser):
                    continue

                # is online?
                if (Data.IS_LOGGED_IN in self.clients.get(user)) and (self.clients.get(user).get(Data.IS_LOGGED_IN)):
                    whoelse.append(user)
                
                # online within elapsed time period?
                elif (Data.LAST_LOGOUT_TIME in self.clients.get(user)) and ((datetime.datetime.now() - self.clients.get(user).get(Data.LAST_LOGOUT_TIME)).total_seconds() <= elapsed):
                    whoelse.append(user)

        # Send intent to user
        self.safeSendAllOrLogout(self.clients.get(fromuser).get(Data.CONNECTION), [
                                 Intents.WHOELSESINCE] + whoelse + [Intents.END_OF_COMMS], 0.1)

    '''
    send all messages to user having "connection". 
    If there is an error, log the user out.
    '''
    def safeSendAllOrLogout(self, connection, messages, timeout):
        for message in messages:
            # Send the message. If there was an error, abort
            if (self.safeSendDataOrLogout(connection, message)):
                return True
            time.sleep(timeout)

    '''
    Broadcast!
    '''
    def userBroadcast(self, fromuser, message):
        data = message.pop(0)
        with self.lock:
            # send message to every client
            for user in self.clients.keys():
                if (user == fromuser):
                    continue

                # if logged in 
                if (Data.IS_LOGGED_IN in self.clients.get(user)) and (self.clients.get(user).get(Data.IS_LOGGED_IN)):
                    self.publicMessage(
                        fromuser, [user, 'Broadcast: ' + data], False)

    '''
    Don't send messages to blocked people
    '''
    def authorizeMessage(self, fromuser, touser):
        with self.lock:
            if (Data.BLOCKED_CLIENTS in self.clients.get(touser).keys()) and (fromuser in self.clients.get(touser).get(Data.BLOCKED_CLIENTS)):
                return False
            return True

    '''
    Send message through the server
    '''
    def publicMessage(self, fromuser, data, storeMessage=True):
        try:
            # get data
            touser, message = data
        except:
            # error check
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
            if (not self.authorizeMessage(fromuser, touser)):
                
                self.safeSendDataOrLogout(
                    connection, Messages.RECIEVER_BLOCKED_SENDER + ' by ' + touser)
                return

            # if the user is not online, store the message instead (if thats what is asked...)
            if (not self.clients.get(touser).get(Data.IS_LOGGED_IN)):
                if (not storeMessage):
                    return
                
                # add unread messages
                if not self.clients.get(touser).get(Data.UNREAD_MESSAGES):
                    self.clients[touser][Data.UNREAD_MESSAGES] = []
                self.clients.get(touser).get(Data.UNREAD_MESSAGES).append(
                    ' >> ' + fromuser + ": " + message)
                self.safeSendDataOrLogout(self.clients.get(fromuser).get(Data.CONNECTION), (
                    ' >> ' + touser + " is not online at the moment. They can look at your message when they come online"))
            # send the message!
            else:
                self.safeSendDataOrLogout(self.clients.get(touser).get(
                    Data.CONNECTION), (' >> ' + fromuser + ": " + message))

    '''
    Handle keyboard interrupts
    '''
    def signal_handler(self, sig, frame):
        # close welcoming socket and exit 
        self.welcSocket.close()
        sys.exit(0)

    '''
    Initialize a p2p connection
    '''
    def initp2p(self, username, connection):
        # Wait for user to send data about its welcsocket and port
        privatedata = self.safeReceiveData(connection)

        # parse and validate the private data
        while (not privatedata) or len(privatedata.split()) < 2:
            self.safeSendDataOrLogout(connection, Intents.WRONGPRIVATEDETAILS)

        # otherwise add it
        ip, port = privatedata.split()
        
        # Store data about the p2p socket
        self.addData(username, Data.PRIVATE_IP, ip)
        self.addData(username, Data.PRIVATE_PORT, port)

    def login(self, connection):
        # receive data in a loop
        while (True):
            try:
                # Get the login details from the client
                loginDetails = self.receiveData(connection)
                details = [x.strip() for x in loginDetails.split()]

                # error check
                if (not (details and len(details) == 2)):
                    self.sendData(connection, Intents.LOGIN_REJECT)
                    time.sleep(0.1)
                    continue

                # extract username and password
                username, passw = details

                # Authorize the client. If it works, send the response back
                response = self.auth.authorize(username, passw)
                
                # internal error
                if (not response):
                    self.sendData('Internal Server Error')
                else:
                    # send response from auth
                    connection.send(response.encode())

                    # Successful login
                    if (response == Intents.AUTH_SUCCESS):
                        # init the server
                        time.sleep(0.1)
                        self.initp2p(username, connection)
                        time.sleep(0.1)
                        self.safeSendDataOrLogout(connection, username)
                        time.sleep(0.1)
                        
                        # store client data
                        self.addClient(connection, username)
                        
                        # Begin thread to timeout the user after the
                        # required number of seconds
                        self.startThread(self.userTimeout, True, [username])
                        return username

            except socket.timeout:
                break
            except Exception as e:
                # check if socket is open. If yes, log user out
                if (not self.checksocket(connection)):
                    self.unexpectedClientClosure()
                    self.logout(connection)
                
                break

    '''
    Check if socket is still connected
    '''
    def checksocket(self, connection):
        try:
            connection.settimeout(2)
            self.sendData(connection, Intents.ACTIVITY_CHECK)
            message = self.receiveData(connection)
            connection.settimeout(None)

            # all good
            if (message.decode() == Intents.ACTIVE):
                return True
            return False
        except (socket.timeout, IOError):
            return False
        except Exception as e:
            return False

    '''
    Make a broadcast!
    '''
    def broadcast(self, message):
        if (not message):
            return

        with self.lock:
            # send message to all clients who are logged in
            for client in self.clients.values():
                try:
                    if (not ((Data.IS_LOGGED_IN in client.keys()) and client.get(Data.IS_LOGGED_IN))):
                        continue
                    client.get(Data.CONNECTION).send(message.encode())
                    
                except socket.timeout:
                    self.logout(client.get(Data.CONNECTION),
                                client.get(Data.USERNAME))
                    break
                except Exception as e:
                    break

    '''
    helper: starts a thread (daemon)
    '''
    def startThread(self, targetFunc, daemon, arguments):
        # Create new thread.
        newthread = threading.Thread(target=targetFunc, args=arguments)
        newthread.daemon = daemon
        newthread.start()
        return newthread

    '''
    Store info about the user
    '''
    def addClient(self, connection, username):
        # Assuming that the client is not logged in yet
        # send broadCast
        self.broadcast(username + ' has joined.')
        with self.lock:
            #     
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

        # init a timeout for logging the user out
        self.addData(username, Data.TIMEOUT, int(self.timeout))

    '''
    Helper. Add data synchronized
    '''
    def addData(self, username, tag, data):
        with self.lock:
            if (username in self.clients):
                self.clients[username][tag] = data

    '''
    Reset user timeout
    '''
    def resetTimeout(self, username):
        with self.lock:
            if (self.clients and self.clients.get(username)):
                self.clients[username][Data.TIMEOUT] = self.timeout

    '''
    Log user out
    '''
    def logout(self, connection, username=None, additionalMessage=None):
        # Remove from active connections
        with self.lock:
            self.activeUsers.pop(connection, None)

        if ((not username) or (username not in self.clients.keys()) or (not self.clients.get(username).get(Data.IS_LOGGED_IN))):
            return
        
        # logout. allows for a login again
        self.auth.logout(username)

        # change state
        self.clients[username][Data.IS_LOGGED_IN] = False
        self.clients[username][Data.LAST_LOGOUT_TIME] = datetime.datetime.now()

        # send any needed additional message before logout
        if (additionalMessage):
            if (not self.safeSendData(connection, additionalMessage)):
                self.endSession(0, connection)
            time.sleep(0.1)

        # Send the user logout message
        self.safeSendData(connection, Intents.LOGOUT)

        # end the current thread
        self.endSession(0, connection)

    '''
    Send data over a connection
    '''
    def sendData(self, connection, message):
        connection.send(message.encode())

    '''
    Unexpected session closure. Handle
    '''
    def unexpectedClientClosure(self):
        pass

        # Possible scenario
        # No need to continue session if client closed
        # self.endSession(0, connection)

    '''
    Cleanup
    '''
    def cleanup(self, connection):
        self.logout(connection, self.activeUsers[connection])
        self.endSession(0, connection)

    '''
    Safety layer over sending data. Replies with whether data could be sent or not
    '''
    def safeSendData(self, connection, message):
        try:
            connection.send(message.encode())
            return True
        except (socket.error, IOError):
            self.unexpectedClientClosure()
            return False

    '''
    Receive data. No error checks
    '''
    def receiveData(self, clientSocket):
        return clientSocket.recv(4096).decode()

    '''
    Receive data, but safely. Returns whether data was received or not
    '''
    def safeReceiveData(self, connection):
        try:
            data = connection.recv(8192).decode()
            return data
        except (socket.error, IOError) as e:
            
            self.unexpectedClientClosure()
            return False


    '''
    Log the client out if he/she does not issue a command in self.timeout seconds
    '''

    def userTimeout(self, username):
        # Decrement inside loop
        while True:
            # 
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
            
            command = self.safeReceiveData(connection)

            # Check if the command is supported
            if ((not command) or command not in self.supportedCommands):
                self.safeSendDataOrLogout(connection, Intents.INVALID_COMMAND)
            else:
                # Recieve all the data client wants to send
                inp = []
                data = self.safeReceiveData(connection)
                while not (data == Intents.END_OF_COMMS):
                    inp.append(data)
                    data = self.safeReceiveData(connection)

                
                # send data to the required function
                self.supportedCommands[command](username, inp)

    '''
    Send data. If that fails, log the user out
    '''
    def safeSendDataOrLogout(self, connection, message, additionalMessage=None):
        if (not self.safeSendData(connection, message)):
            self.logout(
                connection, self.activeUsers[connection], additionalMessage)

    '''
    Init welcoming socket
    '''
    def recvConnection(self):
        # Listen for incoming connections
        self.welcSocket.listen()

        while(True):
            # accept new connection
            connection, addr = self.welcSocket.accept()

            # Create new thread to handle the connection...
            recv_thread = threading.Thread(
                target=self.handleConnection, args=[connection, addr])
            recv_thread.daemon = True
            recv_thread.start()

'''
Extract argument from command line
'''
def getCmdArg(index):
    if index < len(sys.argv) and sys.argv[index]:
        return int(sys.argv[index])

'''
Tell the user how to use the server
'''
def usage():
    print ('Usage: python3 server.py <port number> <block duration> <timeout>')
    sys.exit(0)


# Runner
if __name__ == "__main__":
    # accept data
    serverPort = getCmdArg(1)
    blockDuration = getCmdArg(2)
    timeout = getCmdArg(3)

    if (not (serverPort or blockDuration or timeout)):
        usage()

    server = Server(serverPort, blockDuration, timeout)
    server.recvConnection()
