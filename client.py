import socket

def handle_choice(socket):
    choice = input("\nChoice: ")
    socket.send(choice.encode('utf-8'))
    return choice

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
        print(type(choice))
        while choice  != '4': 
            message = client_socket.recv(1024).decode('utf-8')
            print(message)
            choice = handle_choice(client_socket)
            print(type(choice))
    client_socket.close()  # Close the connection

if __name__ == '__main__':
    client()

