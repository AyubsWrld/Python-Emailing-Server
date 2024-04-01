import socket
from datetime import datetime
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
import os
# To Do:
# Use fork for simnulatneous clients

MENUMSG = "1) Create and send an email\n2) Display the inbox list\n3) Display the email conents\n4) Terminate the connection"
HOST = '127.0.0.1'
PORT = 13000
sym_key = None
username = None
MESSAGES = [
    "Enter the server IP or name: ",
    "Enter your username: ",
    "Enter your password: ",
]
client_public = None

# Get the server private key
with open('server_private.pem', 'r') as ServerPrivate:
    SERVER_PRIVATE = RSA.import_key(ServerPrivate.read())

# Generate SYM KEY
def generate_sym(client_public_key):
    global sym_key
    sym_key = os.urandom(32)
    # Encrypt the symmetric key with the client's public RSA key
    cipher_rsa = PKCS1_OAEP.new(client_public_key)
    enc_sym_key = cipher_rsa.encrypt(sym_key)
    return enc_sym_key

# Decrypt the data using the servers private key
def decrypt_data_with_privatekey(data):
    cipher = PKCS1_OAEP.new(SERVER_PRIVATE)
    decrypted_data = cipher.decrypt(data)
    return decrypted_data.decode()

# Encrypts the data using the sym_key
def encrypt_data_with_sym(data):
    # Ensure the symmetric key (AES key) is 256 bits (32 bytes)
    if len(sym_key) != 32:
        raise ValueError("Symmetric key must be 256 bits (32 bytes) long")

    # Create an AES cipher object in ECB mode
    cipher = AES.new(sym_key, AES.MODE_ECB)

    # Pad the data and encrypt
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return encrypted_data

# Decrypts the data using the sym key
def decrypt_data_with_sym(data):
    # Ensure the symmetric key is 256 bits (32 bytes)
    if len(sym_key) != 32:
        raise ValueError("Symmetric key must be 256 bits (32 bytes) long")

    # Create an AES cipher object in ECB mode
    cipher = AES.new(sym_key, AES.MODE_ECB)

    # Decrypt the data and unpad
    decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
    return decrypted_data.decode()

# Get the clients public_key
def get_client_public_key(username):
    global client_public
    file = f"{username}_public.pem"
    with open(file, 'r') as clientPublic:
        client_public = RSA.import_key(clientPublic.read())

# Validate client
def validate(conn):
    global username
    # Send 'Enter Username'
    conn.send('Enter Username:'.encode('utf-8'))
    encrypted_username = conn.recv(1024)
    username = decrypt_data_with_privatekey(encrypted_username)

    # Send 'Enter Password'
    conn.send('Enter Password:'.encode('utf-8'))
    encrypted_password = conn.recv(1024)
    password = decrypt_data_with_privatekey(encrypted_password)

    # Get users usernames and passwords
    with open('user_pass.json', 'r') as userDatabase:
        data = dict(json.load(userDatabase))
    
    if username in data and data[username] == password:
        get_client_public_key(username)
        enc_sym_key = generate_sym(client_public)
        conn.send(enc_sym_key)
        print(f"Connection Accepted and Symmetric Key Generated for client: {username}")
        return True
    else:
        invalid_message = bytes("Invalid username or password", 'utf-8')
        conn.send(invalid_message)
        print(f"The received client information: {username} is invalid (ConnectionTerminated).")
    return False

def save_email(email: str, recipient_users, title):
    for user in recipient_users:
        file_name = f"./{user}/{user}_{title}.txt"
        with open(file_name, "w") as f:
            f.write(email)
        
# Add time and date to the email information
def modify_email(email: str):
    index = email.find("Title")
    time_and_date = f"Time and Date: {datetime.now()}\n"
    end_email = email[index:]
    email = email[0:index] + time_and_date + end_email
    return email

# Sending email subprotocol
def sending_email_subprotocol(conn):
    # Send email message, encrypted with sym_key
    conn.send(encrypt_data_with_sym("Send the email"))
    email = decrypt_data_with_sym(conn.recv(1024))
    from_email = email
    to_email = email
    content_length = email
    
# Viewing inbox subprotocol
def viewing_inbox_subprotocol(conn):
    pass

# Viewing email subprotocol
def viewing_email_subprotocl(conn):
    pass

# Main server function
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create socket
    server_socket.bind((HOST, PORT))  # Bind to the port
    server_socket.listen(1)  # Listen for incoming connections

    print("Server started. Listening on port 13000.")

    while True:
        conn, address = server_socket.accept()  # Accept a new connection
        print(f"Connection from {address} has been established.")
        user_exists = validate(conn)
        if not user_exists :
            conn.close()
        else:
            ack = conn.recv(1024)
            ack = decrypt_data_with_sym(ack)
            if ack == "OK":
                while True:
                    conn.send(encrypt_data_with_sym(MENUMSG))
                    response = decrypt_data_with_sym(conn.recv(1024))
                    if response == '1':
                        sending_email_subprotocol(conn)
                    elif response == '2':
                        viewing_inbox_subprotocol(conn)
                    elif response == '3':
                        viewing_email_subprotocl(conn)
                    elif response == '4':
                        print(f"Terminating connection with {username}.")
                        break
        conn.close()  # Close the connection

if __name__ == '__main__':
    start_server()