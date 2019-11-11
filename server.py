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

class Server():
    def __init__(self, serverPort = 12000):
        super().__init__()
        self.blockDuration = int(self.getCmdArg(sys.argv, '-block_duration'))
        self.timeout = int(self.getCmdArg(sys.argv, '-timeout'))
        print(str(self.timeout), " ", str(self.blockDuration))
        if (not self.blockDuration or not self.timeout):
            print ('Usage: <Run Command> -block_duration <Block Duration> -timeout <Timeout>')
            sys.exit(0)
        
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

    
    def getCmdArg(self, args, argToFind):
        for arg in range(len(args)):
            if args[arg] == argToFind:
                return args[arg + 1]

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
                        print ('starting timemout thread...')
                        # Begin thread to timeout the user after the
                        # required number of seconds
                        self.startThread(self.userTimeout, True, [connection])
                        return True


            except socket.timeout:
                print ('Internal Server Error: Timeout')
                break
            except Exception as e:
                print (loginDetails)
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
        with self.lock:
            print ('got lock')
            self.clients[connection] = {}
            self.clients[connection][Data.USERNAME] = username
            print ('added user ' + str(self.timeout))
            self.clients[connection][Data.TIMEOUT] = int(self.timeout)

    def addData(self, connection, tag, data):
        with self.lock:
            if (self.clients and self.clients[connection]):
                self.clients[connection][tag] = data

    def resetTimeout(self, connection):
        with self.lock:
            if (self.clients and self.clients[connection]):
                self.clients[connection][Data.TIMEOUT] = self.timeout

    def logout(self, connection, additionalMessage=None):
        if (connection not in self.clients.keys()):
            return

        print ('logging user out ', self.clients[connection])
        self.auth.logout(self.clients[connection][Data.USERNAME])
        self.clients.pop(connection, None)

        # Send the user logout message
        self.safeSendData(connection, Intents.LOGOUT)
        time.sleep(0.1)
        if (additionalMessage):
            self.sendData(connection, additionalMessage)

        if connection.fileno() != -1:
            # print ('')
            connection.close()
            print (connection.fileno())

        # end the current thread
        # sys.exit(0)
    
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
    def userTimeout(self, connection):
        # Decrement inside loop
        while True:
            # Wait for 1 second
            time.sleep(1)

            # Check if user timed out
            with self.lock:
                if (self.clients and self.clients[connection]):
                    if (self.clients[connection][Data.TIMEOUT]):
                        self.clients[connection][Data.TIMEOUT] -= 1
                        if self.clients[connection][Data.TIMEOUT] == 0:
                            self.logout(connection, 'You have been automatically logged out due to inactivity')
                            break
                    else:
                        # Client does not have a timeout. Log him out!
                        self.logout(connection)
                        break
        
        # Do nothing if the client is not logged in

    '''
    Return the list of users who are currently online:
    '''
    def usersCurrentlyOnline(self):
        if (self.clients):
            with self.lock:
                return [self.clients[conn][Data.USERNAME] for conn in self.clients.keys]
        return []

    def handleConnection(self, connection, addr):
        # Connected to a client. Client then sends its intent. Server moves to handle this intent.
        # Get the intent
        intent = self.recieveData(connection)

        # If intent is to login, then log the user in
        if (intent == Intents.LOGIN_USER):
            if (not self.safeSendData(connection, Intents.LOGIN_ACCEPT)):
                return
            self.login(connection)
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

if __name__ == "__main__":
    server = Server()
    server.recvConnection()
