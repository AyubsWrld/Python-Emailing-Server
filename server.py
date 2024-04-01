import socket
import signal
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

def reap_zombie_processes(signum, frame):
    while True:
        try:
            # Wait for completion of a child process without blocking
            pid, _ = os.waitpid(-1, os.WNOHANG)
            if pid == 0:  # No more zombies
                break
        except ChildProcessError:
            # No child processes
            break
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
    from_sender = email[email.find("From: ") + 6: email.find("To: ") - 1]
    to_dest = email[email.find("To: ") + 4: email.find("Title: ") - 1].split(";")
    title = email[email.find("Title: ") + 7: email.find("Content Length: ") - 1]
    content_length = int(email[email.find("Content Length: ") + 16: email.find("Content: ") - 1])
    content = email[email.find("Content: ") + 9:]
    to_dest[-1] = to_dest[-1][:-1] if to_dest[-1][:-1] == ";" else to_dest[-1]
    recipients = ";".join(to_dest)
    print(f"An email from {from_sender} is sent to [{recipients}] has a content length of {content_length}")
    email = modify_email(email)
    for recipient in to_dest:
        title = title.replace(" ", "")
        file = f"./{recipient}/{from_sender}_{title}.txt"
        with open(file, 'w') as e:
            e.write(email)

# Extracts the datetime elemtn in the list, and converts it
def extract_datetime(email_lst):
    return datetime.strptime(email_lst[1], '%Y-%m-%d %H:%M:%S.%f')

# Gets and sorts the clients emails based on date and time
def get_sorted_emails():
    folder = f"./{username}"
    files = [file for file in os.listdir(folder) if os.path.isfile(os.path.join(folder, file))]
    emails = []
    sorted_emails = []
    for file in files:
        file = f"./{username}/{file}"
        with open(file, 'r') as f:
            email = f.read()
        from_sender = email[email.find("From: ") + 6: email.find("To: ") - 1]
        date_time = email[email.find("Time and Date: ") + 15: email.find("Title: ") - 1]
        title = email[email.find("Title: ") + 7: email.find("Content Length: ") - 1]
        e = [from_sender, date_time, title]
        emails.append(e)
    sorted_emails = sorted(emails, key=extract_datetime)
    sorted_emails = sorted_emails[::-1]
    for i in range(len(sorted_emails)):
        sorted_emails[i].insert(0, str(i+1))
    return sorted_emails

# Viewing inbox subprotocol
def viewing_inbox_subprotocol(conn):
    message = "Index    From           DateTime                          Title\n"
    sorted_emails = get_sorted_emails()
    for email in sorted_emails:
        message += "        ".join(email) + "\n"
    conn.send(encrypt_data_with_sym(message))
    ack = decrypt_data_with_sym(conn.recv(1024))
    if not (ack == "OK"):
        print("ACK not recieved!")

# Viewing email subprotocol
def viewing_email_subprotocl(conn):
    conn.send(encrypt_data_with_sym("the server request email index"))
    index = decrypt_data_with_sym(conn.recv(1024))
    emails = get_sorted_emails()
    email = emails[int(index) - 1]
    file = f"./{username}/{username}_{email[3]}.txt"
    with open(file, 'r') as f:
        email = f.read()
    conn.send(encrypt_data_with_sym(email))

def handleClient(conn):
        while True:
            conn.send(encrypt_data_with_sym(MENUMSG))
            response = conn.recv(1024)
            response = decrypt_data_with_sym(response)
            if response == '1':
                sending_email_subprotocol(conn)
            elif response == '2':
                viewing_inbox_subprotocol(conn)
            elif response == '3':
                viewing_email_subprotocl(conn)
            elif response == '4':
                print(f"Terminating connection with {username}.")
                break

# Main server function
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print("Server started. Listening on port 13000.")
    signal.signal(signal.SIGCHLD, reap_zombie_processes)
    while True:
        conn, address = server_socket.accept()
        print(f"Connection from {address} has been established.") 
        user_exists = validate(conn)  
        try:
            pid = os.fork()
            if pid == 0:  # Child process
                server_socket.close()  # Close the listening socket in the child
                if not user_exists:
                    conn.close()  # Close connection if validation fails
                else:
                    # Perform communication with the client
                    ack = conn.recv(1024)
                    ack = decrypt_data_with_sym(ack)  # Assuming decrypt_data_with_sym is defined
                    if ack == "OK":
                        handleClient(conn)  # Your existing client handling function
                    os._exit(0)  # Exit child process
            else:
                conn.close()  # Parent closes the connected socket
        except OSError as e:
            print(f"Failed to fork a new process: {e}")
            conn.close()

if __name__ == '__main__':
    start_server()
