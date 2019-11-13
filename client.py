import socket
import sys
import signal
import time
import threading
import Intents
import select

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

        self.supportedCommands = {'message': self.serverMessage}

    def welcome(self):
        print("Welcome to CmdChat. Finally you get to talk to your friends through the best UI ever: The command line! *Fireworks in background*")
        
    def login(self):
        print ('connecting...')
        self.connectToServer(50)
        print ('connected...')

        # Prime the server by sending an intent to it
        if (self.safeSendData(Intents.LOGIN_USER)):
            print ('Server cannot be reached')
            self.endClient(0)

        print ('sent data')

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
                print (response.decode())
                self.onConnected()
                return True
            else:
                if (response):
                    print(response.decode(), '\n')
                else:
                    print ('Internal Server Error')
                    self.endClient(1)
    
    def onConnected(self):
        self.isLoggedIn = True
        # Thread to recieve data
        recv_thread=threading.Thread(target=self.handleCommands)
        recv_thread.daemon=True
        recv_thread.start()

        # self.safeRecieveData()

    # def handleClose(self, connection):
    #     while (True):
    #         if (connection.fileno() == -1):
    #             print ('Server closed connection unexpectedly')
    #             self.endClient(1)
    #         time.sleep(1)
    #         print(connection.fileno())

    def unexpectedClose(self):
        print ('The connection was closed unexpectedly')

    def safeSendData(self, message):
        try:
            self.clientSocket.send(message.encode())
        except socket.error:
            self.unexpectedClose()
            return True
        except IOError:
            self.unexpectedClose()
            return True

    def safeSendAll(self, messages, timeout):
        for message in messages:
            # Send the message. If there was an error, abort
            if (self.safeSendData(message)):
                return True
            time.sleep(timeout)

    def serverMessage(self, userInput):
        if (not userInput) or (len(userInput) < 2):
            return False
            
        user = userInput[1]
        message = ' '.join(userInput[2:])
        self.safeSendAll([Intents.MESSAGE, user, message], 1)

    def handleCommands(self):
        while (True):
            inp = input("$ ").strip().split()
            
            # Extract command and params
            command = inp[0]

            if (command in self.supportedCommands):
                self.supportedCommands[command](inp)



    def checksocket(self):
        while True:
            try:
                ret = select.select([self.clientSocket], [], [], 5)
                
                print(ret)
                if (self.clientSocket in ret[0]):
                    print ('was readable')
                    continue
                else:
                    print ('nope')
                    self.logout()
                    break
                print(ret)
            except Exception as e:
                print ('Exception checking socket ---> ', e)
                break

    def safeRecieveData(self):
        while (True):
            # self.clientSocket.settimeout(2)
            try:
                # print ('recieving data')
                message = self.clientSocket.recv(2048)

                # logout if needed
                # if (message.decode() == Intents.LOGOUT):
                #     print (self.clientSocket.recv(2048).decode())
                #     self.logout()

                # otherwise print the reponse out
                print (message.decode())
                return message.decode()

                # Reset timeout
                # self.clientSocket.settimeout(None)

                # time.sleep(1)
            # except socket.timeout:
            #     print ('timeout')
            #     continue
            except socket.error or IOError:
                self.unexpectedClose()
                self.logout()
            except Exception as e:
                print ('Exception while recieving data ---> ', e)
                break
    
    def logout(self):
        print('Exiting...')
        self.endClient(0)

    def handleTimeout(self):
        pass

    def connectToServer(self, timeoutT):
        self.clientSocket.connect((self.serverIP, self.serverPort))

    def sendDataToServer(self, message):
        # Send message to the server
        try:
            if self.clientSocket.fileno() != -1:
                self.clientSocket.send(message.encode())
                #wait for the reply from the server
                recievedMessage = self.clientSocket.recv(2048)
                return recievedMessage
        except socket.timeout:
            print ('Connection timed out')
            self.clientSocket.close()
        except Exception as e:
            print(e)

    def signal_handler(self, sig, frame):
        self.endClient()

    def endClient(self, exitCode = 0):
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
    print ('Usage: python3 client.py <Server Ip Address> <Server Port No>')
    sys.exit(0)

if __name__ == "__main__":
    serverIP = getCmdArg(1)
    serverPort = None
    if (getCmdArg(2)):
        serverPort = int(getCmdArg(2))

    if (not (serverPort or serverIP)):
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