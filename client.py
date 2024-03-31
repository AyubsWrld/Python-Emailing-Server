import socket

def handle_choice(socket):
    choice = input("\nChoice: ")
    socket.send(choice.encode('utf-8'))
    return choice

def handleOne(socket):
    response = socket.recv(1024).decode()
    print(response, end = '')
    clients = input()
    socket.send(clients.encode('utf-8'))

    response = socket.recv(1024).decode()
    print(response, end = '')
    title = input()
    socket.send(title.encode('utf-8'))

    response = socket.recv(1024).decode()
    print(response, end = '')
    loadContents = input()
    socket.send(loadContents.encode('utf-8'))

    response = socket.recv(1024).decode()
    print(response, end = '')
    filename = input()
    socket.send(filename.encode('utf-8'))
    print('The message is sent to the server \n')

def handleThree(socket):
    MESSAGE = socket.recv(1024).decode()
    response = input(MESSAGE)

    socket.send(response.encode('utf-8'))

def validate(conn):
    message = conn.recv(1024).decode('utf-8') 
    x = input(message)
    conn.send(x.encode('utf-8'))
    message = conn.recv(1024).decode('utf-8') 
    x = input(message)
    conn.send(x.encode('utf-8'))
    message = conn.recv(1024).decode('utf-8') 
    x = input(message)
    conn.send(x.encode('utf-8'))
    ACK = conn.recv(1024).decode('utf-8')
    return ACK

def client():
    host = '127.0.0.1'  # Server's IP address
    port = 13000  # The same port as the server

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create socket
    client_socket.connect((host, port))  # Connect to the serverA

    validation_state = validate(client_socket)
    message = client_socket.recv(1024).decode('utf-8')
    print(message)
    if validation_state == 'True' : 
        choice = handle_choice(client_socket)
        while choice != '4': 
            if choice == '1' : 
                handleOne(client_socket)
            elif choice == '3' : 
                handleThree(client_socket)
            message = client_socket.recv(1024).decode('utf-8')
            print(message)
            choice = handle_choice(client_socket)
    client_socket.close()  # Close the connection

if __name__ == '__main__':
    client()

