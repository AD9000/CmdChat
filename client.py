from socket import *
import sys
import signal

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
        response = self.sendDataToServer(message)

        print(response)
    
    def handleRequests(self):
        while (True):
            pass

    def connectToServer(self):
        self.clientSocket.connect((self.serverName, self.serverPort))
        
    def sendDataToServer(self, message):
        # Send message to the server
        self.clientSocket.send(message.encode())

        #wait for the reply from the server
        # receivedMessage, serverAddress = self.clientSocket.recvfrom(2048)
        # return receivedMessage

    def signal_handler(self, sig, frame):
        self.endClient()
        sys.exit(0)

    def endClient(self):
        # Close the socket
        self.clientSocket.close()    

    
if __name__ == "__main__":
    client = Client(8080)
    client.connectToServer()
    client.sendDataToServer("lets see if this works...")
    # client.welcome()
    # if (client.login()):
    #     client.handleRequests()