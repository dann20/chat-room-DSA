import os
import logging
import pickle
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread

from DSA import DSA
from RSA import RSAKey

class Server:
    def __init__(self, host, port, file_port, buf_size, private_key, public_key_dict):
        self.CLIENTS = {}
        self.ADDRESSES = {}
        self.FILE_ADDRESSES = {}

        self.HOST = host
        self.PORT = port
        self.FILE_PORT = file_port
        self.ADDR = (host, port)
        self.FILE_ADDR = (host, file_port)
        self.BUFSIZE = buf_size

        self.public_key_dict = public_key_dict

        self.dsa = DSA(private_key)
        self.dsa.create_signer()

        self.server_socket = socket(AF_INET, SOCK_STREAM)
        self.server_socket.bind(self.ADDR)

        self.file_server_socket = socket(AF_INET, SOCK_STREAM)
        self.file_server_socket.bind(self.FILE_ADDR)

    def run_thread(self):
        self.server_socket.listen(5)
        self.file_server_socket.listen(5)

        logging.info('Waiting for incuming connection(s)....')

        self.accept_thread = Thread(target=self.accept_incoming_connections)
        self.file_accept_thread = Thread(target=self.file_accept_incoming_connections)

        self.accept_thread.start()
        self.file_accept_thread.start()

        self.accept_thread.join()
        self.file_accept_thread.join()

        self.server_socket.close()
        self.file_server_socket.close()

    def create_msg(self, msg):
        msg_dict = {"username": 'SERVER',
                    "message": msg,
                    "signature": self.dsa.sign_message(msg),
                    "type": "message"}
        msg_dump = pickle.dumps(msg_dict)
        return msg_dump

    def accept_incoming_connections(self):
        """Sets up handling for incoming clients."""
        while True:
            client, client_address = self.server_socket.accept()
            logging.info("%s:%s has connected." % client_address)
            msg = "Greetings! Enter anything to start chatting!"
            client.send(self.create_msg(msg))
            self.ADDRESSES[client] = client_address
            Thread(target=self.handle_client, args=(client,)).start()


    def handle_client(self, client):  # Takes client socket as argument.
        """Handles a single client connection."""
        try:
            msg_name_dump = client.recv(self.BUFSIZE)
            msg_name = pickle.loads(msg_name_dump)
            if not self.is_authentic(msg_name):
                print(f'Name message {msg_name} failed verification')
                return
            else:
                welcome = 'Welcome %s! If you want to quit, type !quit to exit.' % msg_name['username']
                client.send(self.create_msg(welcome))
                msg = "%s has joined the chat!" % msg_name['username']
                self.CLIENTS[client] = msg_name['username']
                self.broadcast(self.create_msg(msg))

                while True:
                    msg_dump = client.recv(BUFSIZE)
                    msg = pickle.loads(msg_dump)
                    if self.is_authentic(msg):
                        if msg['message'] != "!quit":
                            self.broadcast(msg_dump)
                        else:
                            client.close()
                            del self.CLIENTS[client]
                            self.broadcast(self.create_msg("%s has left the chat." % msg['username']))
                            break
                    else:
                        continue
        except Exception as ex:
            logging.error(ex)

    def is_authentic(self, msg_dict):
        signature = msg_dict['signature']
        message = msg_dict['message']
        public_key = self.public_key_dict[msg_dict['username']]
        if self.dsa.verify_message(signature, message, public_key):
            return True
        else:
            return False

    def broadcast(self, msg_dump):
        """Broadcasts a message to all the clients."""

        for sock in self.CLIENTS:
            sock.send(msg_dump)


    def receive_file(self, sock, filename):
        with open(filename, 'wb') as f:
            while True:
                data = sock.recv(BUFSIZE)
                if not data:
                    f.close()
                    break
                f.write(data)
            print("File Received")
        sock.close()

    def file_accept_incoming_connections(self):
        while True:
            client, _ = self.file_server_socket.accept()
            filename = "received_file"  # Take from sender
            Thread(target=self.receive_file, args=(client, filename,)).start()

if __name__ == '__main__':
    fmt = '[%(levelname)s] %(asctime)s - %(message)s'
    logging.basicConfig(level=logging.INFO, format=fmt)

    HOST = '127.0.0.1'
    PORT = 22020
    FILE_PORT = 22021
    BUFSIZE = 2048

    private_key = RSAKey.from_json_file(f'../keys/private/SERVER.json')

    files = os.listdir('../keys/public')
    public_key_dict = {f[:-12]: RSAKey.from_json_file(f'../keys/public/{f}') for f in files}

    server = Server(HOST, PORT, FILE_PORT, BUFSIZE, private_key, public_key_dict)
    server.run_thread()
