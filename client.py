from socket import *
import sys
import signal
import time
import Intents

class Client():
    def __init__(self, port):

        # HARCODED VALUES!??
        self.serverName = 'localhost'
        self.serverPort = 12000


        self.clientPort = port
        # Socket
        self.clientSocket = socket(AF_INET, SOCK_STREAM)
        # Signal handler
        signal.signal(signal.SIGINT, self.signal_handler)

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
                break
            else:
                if (response):
                    print(response.decode())
                else:
                    print ('Internal Server Error')
                    self.endClient(1)
    
    def handleRequests(self):
        while (True):
            pass

    def handleTimeout(self):
        pass

    def connectToServer(self, timeoutT):
        self.clientSocket.connect((self.serverName, self.serverPort))

    def sendDataToServer(self, message):
        # Send message to the server
        try:
            if self.clientSocket.fileno != -1:
                print ('----sending data-------->')
                self.clientSocket.send(message.encode())
                #wait for the reply from the server
                print ('<---------recieving data----')
                recievedMessage = self.clientSocket.recv(2048)
                return recievedMessage
        except timeout:
            print ('Connection timed out')
            self.clientSocket.close()
        except Exception as e:
            print(e)

    def signal_handler(self, sig, frame):
        self.endClient()

    def endClient(self, exitCode = 0):
        # Close the socket
        self.clientSocket.close()   
        sys.exit(exitCode) 

    
if __name__ == "__main__":
    client = Client(8080)

    # Client is welcomed
    client.welcome()

    # Must login before using anything.
    client.login()

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