import socket
import sys
import signal
import time
import threading
import Intents
import select

class Client():
    def __init__(self, port):

        # HARCODED VALUES!??
        self.serverName = 'localhost'
        self.serverPort = 12000

        self.isLoggedIn = False


        self.clientPort = port
        # Socket
        self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Signal handler
        signal.signal(signal.SIGINT, self.signal_handler)

        self.lock = threading.Condition()

    def welcome(self):
        print("Welcome to CmdChat. Finally you get to talk to your friends through the best UI ever: The command line! *Fireworks in background*")
        
    def login(self):
        self.connectToServer(50)

        # Prime the server by sending an intent to it
        self.sendDataToServer(str(Intents.LOGIN_USER))

        # Get the username and password and try to login
        while (True):
            print("Enter your username")
            username = input('$ ')
            print("Enter your password")
            password = input('$ ')
            message = username + " " + password

            # Try to log the user in:
            response = self.sendDataToServer(message)
            if (response == b'Login Successful'):
                self.onConnected()
                return True
            else:
                if (response):
                    print(response.decode())
                else:
                    print ('Internal Server Error')
                    self.endClient(1)
    
    def onConnected(self):
        self.isLoggedIn = True
        # Thread to recieve data
        recv_thread=threading.Thread(target=self.handleCommands)
        recv_thread.daemon=True
        recv_thread.start()

        self.safeRecieveData()

    # def handleClose(self, connection):
    #     while (True):
    #         if (connection.fileno() == -1):
    #             print ('Server closed connection unexpectedly')
    #             self.endClient(1)
    #         time.sleep(1)
    #         print(connection.fileno())


    def handleCommands(self):
        while (True):
            input()

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
            self.clientSocket.settimeout(2)
            try:
                # print ('recieving data')
                message = self.clientSocket.recv(2048)

                # logout if needed
                if (message.decode() == Intents.LOGOUT):
                    print (self.clientSocket.recv(2048).decode())
                    self.logout()

                # otherwise print the reponse out
                print (message.decode())

                # Reset timeout
                self.clientSocket.settimeout(None)

                time.sleep(2)
            except socket.timeout:
                continue
            except Exception as e:
                print ('Exception while recieving data ---> ', e)
                break
    
    def logout(self):
        print('Exiting...')
        self.endClient(0)

    def handleTimeout(self):
        pass

    def connectToServer(self, timeoutT):
        self.clientSocket.connect((self.serverName, self.serverPort))

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

    
if __name__ == "__main__":
    client = Client(8080)

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