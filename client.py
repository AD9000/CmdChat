from socket import *
import sys
import signal
import time

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
        print("Enter your username")
        username = input()
        print("Enter your password")
        password = input()
        message = username + " " + password

        # Try to log the user in:
        self.connectToServer(5)
        response = self.sendDataToServer(message)

        print(response)
    
    def handleRequests(self):
        while (True):
            pass

    def connectToServer(self, timeoutT):
        self.clientSocket.connect((self.serverName, self.serverPort))
        self.clientSocket.settimeout(timeoutT)

    def sendDataToServer(self, message):
        # Send message to the server
        try:
            if self.clientSocket.fileno != -1:
                self.clientSocket.send(message.encode())
                #wait for the reply from the server
                receivedMessage = self.clientSocket.recv(2048)
                return receivedMessage
        except timeout:
            print ('Connection timed out')
            self.clientSocket.close()
        except Exception as e:
            print(e)
        

    def signal_handler(self, sig, frame):
        self.endClient()
        sys.exit(0)

    def endClient(self):
        # Close the socket
        self.clientSocket.close()    

    
if __name__ == "__main__":
    client = Client(8080)
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