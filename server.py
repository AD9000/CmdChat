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

class Server():
    def __init__(self, serverPort = 12000, blockDuration=10, timeout=1000):
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
        self.clients = {}

        # Yet to figure out the use for these
        self.Update_Interval = 1

    
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

    def login(self, connection):
        # recieve data in a loop
        while (True):
            try:
                # Get the login details from the client
                print('starting again...')
                loginDetails = self.recieveData(connection)
                username, passw = [x.strip() for x in loginDetails.split()]

                # Authorize the client. If it works, send the response back
                response = self.auth.authorize(username, passw)
                print ('Auth response: ------> ', response)

                print (loginDetails)
                print (username, passw)

                if (not response):
                    connection.send(b'Internal Server Error')
                else:
                    print ('sending the response back to the clients')
                    print (response)
                    connection.send(response.encode())
                    print ('response sent')

                    if (response == Intents.AUTH_SUCCESS):
                        print ('yes indeed')
                        self.addClient(connection, username)
                        print ('starting timeout thread...')
                        # Begin thread to timeout the user after the
                        # required number of seconds
                        self.startThread(self.userTimeout, True, [username])
                        return username


            except socket.timeout:
                print ('Internal Server Error: Timeout')
                break
            except Exception as e:
                print ('exception during client login-----> ', loginDetails)
                # print (username, passw)
                print (e)
                if (self.checksocket(connection)):
                    print ('unexpected client closure')
                    self.logout(connection)
                else:
                    print ('Invalid format!')
                break
    
    def checksocket(self, connection):
        try:
            ret = select.select([connection], [], [], 0.5)
            if (connection in ret[0]):
                return True
            else:
                return False
        except Exception as e:
            print ('Exception checking socket ---> ', e)
            return False


    def broadcast(self, message):
        print (message)
        if (not message):
            return
        print (self.clients)
        
        with self.lock:
            for client in self.clients.keys():
                try:
                    print(client)
                    client.send(message.encode())
                    print ('broadcast sent')
                except socket.timeout:
                    self.logout(client)
                except Exception as e:
                    print ('exception while broadcasting ----> ' + str(e))

    def startThread(self, targetFunc, daemon, arguments):
        # Create new thread.
        newthread=threading.Thread(target=targetFunc, args=arguments)
        newthread.daemon=daemon
        newthread.start()
        return newthread

    def addClient(self, connection, username):
        # Assuming that the client is not logged in yet
        # send broadCast
        self.broadcast(username + ' has joined.')
        # with self.lock:
        #     print ('got lock')
        if username not in self.clients.keys():
            self.clients[username] = {}

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
            if (self.clients and self.clients[username]):
                self.clients[username][Data.TIMEOUT] = self.timeout

    def logout(self, username, additionalMessage=None):
        if (username not in self.clients.keys()):
            return

        connection = self.clients[username][Data.CONNECTION]

        print ('logging user out ', self.clients[username])
        self.auth.logout(self.clients[username][Data.CONNECTION])
        self.clients[username][Data.IS_LOGGED_IN] = False
        self.clients[username][Data.LAST_LOGOUT_TIME] = datetime.datetime.now()

        # Send the user logout message
        self.safeSendData(connection, Intents.LOGOUT)
        time.sleep(0.1)
        if (additionalMessage):
            self.sendData(connection, additionalMessage)

        if connection.fileno() != -1:
            # print ('')
            connection.close()
            print (connection.fileno())
        
        print(self.clients[username])

        # end the current thread
        self.endSession(0)
    
    def sendData(self, connection, message):
        connection.send(message.encode())

    def safeSendData(self, connection, message):
        try:
            connection.send(message.encode())
            return True
        except:
            if (not self.isClosed(connection)):
                connection.close()
            return False

    def recieveData(self, clientSocket):
        return clientSocket.recv(2048).decode()

    def safeRecieveData(self, connection):
        try:
            data = connection.recv(8192).decode()
            if (data == Intents.LOGOUT):
                self.logout()
            return data
        except:
            self.logout()
    
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
                    if (self.clients[username][Data.TIMEOUT]):
                        self.clients[username][Data.TIMEOUT] -= 1
                        if self.clients[username][Data.TIMEOUT] == 0:
                            self.logout(username, '\n\nYou have been automatically logged out due to inactivity')
                            break
                    else:
                        # Client does not have a timeout. Log him out!
                        self.logout(username)
                        break
        
        # Do nothing if the client is not logged in

    '''
    Return the list of users who are currently online:
    '''
    def usersCurrentlyOnline(self):
        if (self.clients):
            with self.lock:
                return [self.clients[user][Data.CONNECTION] for user in self.clients.keys]
        return []

    '''
    History: Provides the list of all users online within the given time (in seconds)
    '''
    def userOnlineHistory(self, time):
        users = []
        with self.lock:
            for conn in self.clients.values():
                # if the user is logged in, add him
                if conn[Data.IS_LOGGED_IN]:
                    users.append(conn[Data.USERNAME])
                else:
                    if conn[Data.LAST_LOGOUT_TIME] > datetime.datetime.now() - datetime.timedelta(seconds=time):
                        users.append(conn[Data.USERNAME])

    '''
    Message Forwarding: Server recieves a message from a client and then forwards it over to the recipient
    '''
    def messageForwarding(self):
        # TODO: To be implemented
        pass

    '''
    Ends the current session with the client
    Note: The server can still accept new clients after this operation
    '''
    def endSession(self, exitCode=0):
        sys.exit(exitCode)

    '''
    Handles an incoming connection
    '''
    def handleConnection(self, connection, addr):
        # Connected to a client. Client then sends its intent. Server moves to handle this intent.
        # Get the intent
        intent = self.recieveData(connection)
        check = False

        # If intent is to login, then log the user in
        if (intent == Intents.LOGIN_USER):
            username = self.login(connection)
            if not username:
                # End session immediately
                self.endSession()

            elif (not self.safeSendData(connection, Intents.LOGIN_ACCEPT)):
                self.logout(self.clients[username])
        else:
            # User cannot do anything else before logging in.
            self.safeSendData(connection, Intents.LOGIN_REJECT)

    def recvConnection(self):
        # Listen for incoming connections
        self.welcSocket.listen()

        while(1):
            print('Waiting for connections...')
            connection, addr = self.welcSocket.accept()
            
            # Create new thread to handle the connection...
            recv_thread=threading.Thread(name="ClientHandler", target=self.handleConnection, args=[connection, addr])
            recv_thread.daemon=True
            recv_thread.start()

    def threadSender(self, clientSocket, addr):
        #get lock as we might me accessing some shared data structures
        with self.lock:
            try:
                clientSocket.send("data")
            except socket.error:
                print ('timed out')
            finally:
                self.lock.notify()

    
    def threadReciever(self, clientSocket, addr):
        while (True):
            message = None
            try:
                message = clientSocket.recv(2048)
            except socket.timeout:
                print ('timed out')
                clientSocket.close()
                break

            #get lock as we might me accessing some shared data structures
            if (message):
                print (message)
                try:
                    # Get data from the message
                    username, passw = message.decode().split()
                    # print ('authorizing...')
                    response = self.auth.authorize(username, passw)
                    # print ("got response")
                    clientSocket.send(response.encode())
                    print ('done!')
                    break
                except:
                    return 'Invalid Message'



#will store clients info in this list
# would communicate with clients after every second
# timeout=False


# def recv_handler():
#     while(1):
#         message, clientAddress = serverSocket.recvfrom(2048)
#         #received data from the client, now we know who we are talking with
#         message = message.decode()
#         #get lock as we might me accessing some shared data structures
#         with t_lock:
#             currtime = dt.datetime.now()
#             date_time = currtime.strftime("%d/%m/%Y, %H:%M:%S")
#             print('Received request from', clientAddress[0], 'listening at', clientAddress[1], ':', message, 'at time ', date_time)
#             if(message == 'Subscribe'):
#                 #store client information (IP and Port No) in list
#                 clients.append(clientAddress)
#                 serverMessage="Subscription successfull"
#             elif(message=='Unsubscribe'):
#                 #check if client already subscribed or not
#                 if(clientAddress in clients):
#                     clients.remove(clientAddress)
#                     serverMessage="Subscription removed"
#                 else:
#                     serverMessage="You are not currently subscribed"
#             else:
#                 serverMessage="Unknown command, send Subscribe or Unsubscribe only"
#             #send message to the client
#             serverSocket.sendto(serverMessage.encode(), clientAddress)
#             #notify the thread waiting
#             t_lock.notify()


# def send_handler():
#     global t_lock
#     global clients
#     global clientSocket
#     global serverSocket
#     global timeout
#     #go through the list of the subscribed clients and send them the current time after every 1 second
#     while(1):
#         #get lock
#         with t_lock:
#             for i in clients:
#                 currtime =dt.datetime.now()
#                 date_time = currtime.strftime("%d/%m/%Y, %H:%M:%S")
#                 message='Current time is ' + date_time
#                 clientSocket.sendto(message.encode(), i)
#                 print('Sending time to', i[0], 'listening at', i[1], 'at time ', date_time)
#             #notify other thread
#             t_lock.notify()
#         #sleep for UPDATE_INTERVAL
#         time.sleep(UPDATE_INTERVAL)

# #we will use two sockets, one for sending and one for receiving
# clientSocket = socket(AF_INET, SOCK_DGRAM)

# recv_thread=threading.Thread(name="RecvHandler", target=recv_handler)
# recv_thread.daemon=True
# recv_thread.start()

# send_thread=threading.Thread(name="SendHandler",target=send_handler)
# send_thread.daemon=True
# send_thread.start()
# #this is the main thread
# while True:
#     time.sleep(0.1)

def getCmdArg(index):
    if index < len(sys.argv) and sys.argv[index]:
        return int(sys.argv[index])

def usage():
    print ('Usage: python3 server.py <Port Number> <Block Duration> <Timeout>')
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
