import socket
import threading
import time
import datetime as dt
import signal
import sys

class Authorization():
    def __init__(self):
        self.authdict = {}
        f = open('credentials.txt', 'r')
        for line in f:
            user, passw = line.split()
            self.authdict[user] = passw

    def authorize(self, username, password):
        if username in self.authdict.keys():
            return self.authdict[username] == password

    def createAccount(self, username, passw):
        f = open('credentials.txt', 'a')
        f.write(username + ' ' + passw)

class Server():
    def __init__(self, serverPort = 12000):
        super().__init__()
        self.auth = Authorization()
        self.welcSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.welcSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.welcSocket.bind(('localhost', serverPort))
        self.lock = threading.Condition()

        # Signal handler
        signal.signal(signal.SIGINT, self.signal_handler)

        # Yet to figure out the use for these
        self.clients = []
        self.Update_Interval = 1
        self.timeout = False

    
    def signal_handler(self, sig, frame):
        print("\nShutting down server...")
        self.welcSocket.close()
        sys.exit(0)


    def signup(self, username, passw):
        self.auth.createAccount(username, passw)

    def recvConnection(self):
        # Listen for incoming connections
        self.welcSocket.listen(5)

        while(1):
            print('Waiting for connections...')
            connection, addr = self.welcSocket.accept()
            
            # Create new thread to handle the connection...
            recv_thread=threading.Thread(name="RecvHandler", target=self.threadReciever, args=[connection, addr])
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
        clientSocket.settimeout(1)
        while (True):
            try:
                message = clientSocket.recv(2048)
            except socket.timeout:
                print ('timed out')
                clientSocket.close()
                return
            #get lock as we might me accessing some shared data structures

            if (message):
                with self.lock:
                    username, passw = message.decode().split()
                    if (self.auth.authorize(username, passw)):
                        clientSocket.send(b"Login Successful")
                    self.lock.notify()



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
