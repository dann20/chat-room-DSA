import os
import logging
import pickle
from socket import AF_INET, socket, SOCK_STREAM

from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QFileDialog, QMessageBox, QWidget

from DSA import DSA
from RSA import RSAKey

from design_chat import Ui_MainWindow

BUFSIZE = 2048

class ChatGUI(Ui_MainWindow):
    def __init__(self, username, client_socket, file_addr, private_key, public_key_dict):
        super().__init__()
        self.username = username
        self.client = client_socket
        self.private_key = dict()
        self.dsa = DSA(private_key=private_key)
        self.dsa.create_signer()
        self.public_key_dict = public_key_dict
        self.FILE_ADDR = file_addr
        self.worker = WorkerThread(client_socket, username, self.dsa, public_key_dict)
        self.worker.start()

    def link(self):
        self.message.returnPressed.connect(self.send)
        self.send_btn.clicked.connect(self.send)
        self.worker.update_log.connect(self.append_message)

    def send(self):
        msg = self.message.text()
        msg_dict = {"username": self.username,
                    "message": msg,
                    "signature": self.dsa.sign_message(msg),
                    "type": "message"}
        msg_dict_dump = pickle.dumps(msg_dict)
        self.client.send(msg_dict_dump)
        display_text = f"{self.username}: {msg}"
        self.chat_log.append(display_text)
        self.message.clear()
        if msg == "!quit":
            self.client.close()
            QtWidgets.qApp.quit()
            # close main window, return to login window
            pass

    def send_file(self):
        file_filter = "All Files (*)"
        filename, _ = QFileDialog.getOpenFileName(
            parent=self.groupBox,
            caption='Select a file to send',
            directory='../files',
            filter=file_filter
        )
        if not filename:
            return False
        try:
            signature = self.dsa.sign_file(filename)
            pass
            s = socket(AF_INET, SOCK_STREAM)
            s.connect(self.FILE_ADDR)

            with open(filename, "rb") as f:
                l = f.read(BUFSIZE)
                msg_dict_dump = self.create_chunk_file_msg(filename, l, signature)
                while l:
                    s.send(msg_dict_dump)
                    l = f.read(BUFSIZE)
                    msg_dict_dump = self.create_chunk_file_msg(filename, l)
                s.close()

            display_text = f"{self.username} sent a file {filename}."
            self.chat_log.append(display_text)
        except Exception as ex:
            logging.error(ex)
            self.show_popup('Cannot send file.', QMessageBox.Critical)

    def create_chunk_file_msg(self, filename, chunk, signature=None):
        msg_dict = {"username": self.username,
                    "filename": filename,
                    "file_data": chunk,
                    "signature": signature,
                    "type": "file_transfer"}
        msg_dict_dump = pickle.dumps(msg_dict)
        return msg_dict_dump

    def show_popup(self, text, icon=QMessageBox.Question):
        msg = QMessageBox()
        msg.setWindowTitle('DSA')
        msg.setText(text)
        msg.setIcon(icon)
        msg.setStandardButtons(QMessageBox.Ok)
        _ = msg.exec_()

    def append_message(self, text):
        self.chat_log.append(text)
        # app_thread = QtWidgets.QApplication.instance().thread()
        # curr_thread = QtCore.QThread.currentThread()
        # if app_thread != curr_thread:
        #     raise Exception('attempt to call MainWindow.append_message from non-app thread')
        # else:
        #     logging.info('Normal')

class WorkerThread(QThread):
    update_log = pyqtSignal(str)

    def __init__(self, client_socket, username, dsa, public_key_dict):
        super().__init__()
        self.client_socket = client_socket
        self.username = username
        self.dsa = dsa
        self.public_key_dict = public_key_dict

    def run(self):
        while True:
            try:
                msg_dump = self.client_socket.recv(BUFSIZE)
                msg_dict = pickle.loads(msg_dump)
                if msg_dict['username'] == self.username:
                    continue
                if self.dsa.verify_message(msg_dict['signature'], msg_dict['message'], self.public_key_dict[msg_dict['username']]):
                    display_text = f"{msg_dict['username']}: {msg_dict['message']}"
                else:
                    display_text = f"Message {msg_dict} failed verification."
                self.update_log.emit(display_text)
            except OSError:
                break

if __name__ == '__main__':
    fmt = '[%(levelname)s] %(asctime)s - %(message)s'
    logging.basicConfig(level=logging.INFO, format=fmt)

    # HOST = input('Enter server address: ')
    # PORT = input('Enter server message port: ')
    # FILE_PORT = input('Enter server file port: ')
    # USERNAME = input('Enter your username: ')
    HOST = '127.0.0.1'
    PORT = 22020
    FILE_PORT = 22021
    USERNAME = input('Enter your username: ')

    MESSAGE_ADDR = (HOST, int(PORT))
    FILE_ADDR = (HOST, int(FILE_PORT))

    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(MESSAGE_ADDR)

    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()

    private_key = RSAKey.from_json_file(f'../keys/private/{USERNAME}.json')

    files = os.listdir('../keys/public')
    public_key_dict = {f[:-12]: RSAKey.from_json_file(f'../keys/public/{f}') for f in files}
    print(public_key_dict)

    ui = ChatGUI(USERNAME, client_socket, FILE_ADDR, private_key, public_key_dict)
    ui.setupUi(MainWindow)
    ui.link()
    MainWindow.show()
    sys.exit(app.exec_())
