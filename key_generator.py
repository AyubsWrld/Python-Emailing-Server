from Crypto.PublicKey import RSA

def generate_keys(key_size=2048):
    """
    Generate RSA private and public keys.
    
    :param key_size: The size of the key to generate in bits.
    :return: private_key, public_key
    """
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_keys(private_key, public_key, private_file_name, public_file_name):
    """
    Save the private and public keys to files.

    :param private_key: The private key to save.
    :param public_key: The public key to save.
    :param private_file_name: The filename to save the private key.
    :param public_file_name: The filename to save the public key.
    """
    with open(private_file_name, 'wb') as priv_file:
        priv_file.write(private_key)

    with open(public_file_name, 'wb') as pub_file:
        pub_file.write(public_key)

# Server and Clients
server_and_clients = ['server','client1', 'client2', 'client3','client4', 'client5']

# For each server/client generate the public/private keys and save them in their respective files
for sc in server_and_clients:
    private_file_name = f'{sc}_private.pem'
    public_file_name = f'{sc}_public.pem'

    private_key, public_key = generate_keys()
    save_keys(private_key, public_key, private_file_name, public_file_name)