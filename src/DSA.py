import logging

from SHA3 import sha3_224, sha3_256, sha3_384, sha3_512
from RSA import RSAKey, RSA
from utils import *

SHA_VER = {'SHA3-224': sha3_224,
           'SHA3-256': sha3_256,
           'SHA3-384': sha3_384,
           'SHA3-512': sha3_512}

class DSA:
    def __init__(self, private_key=None):
        self.config = {
            "e": "19853061807268348331",
            "sha": "SHA3-512",
            "key_size": "2048"
        }

        self.KEYS = ['N', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qinv']

        self.set_sha(self.config['sha'])
        self.set_private_key(private_key)

    def set_private_key(self, private_key):
        self.private_key = private_key

    def create_signer(self):
        self.signer = RSA(self.private_key)

    def set_sha(self, sha):
        self.sha = SHA_VER[sha]

    def keygen(self, bits, e):
        if not bits:
            bits = self.config['key_size']
        if not e:
            e = self.config['e']
        key = RSAKey(bits=int(bits), e=int(e))
        self.set_private_key(key)
        key.public_to_json_file()

    def sign_message(self, message):
        sha = self.sha()

        logging.info('Signing message: %s' % message)
        sha.update(message.encode('ascii'))

        digest = sha.hexdigest()
        logging.info('Digest: %s' % digest)
        signature = self.signer.sign_data(digest.encode('ascii'))
        logging.info('Signature: %s' % signature)
        return signature

    def verify_message(self, signature, message, public_key):
        sha = self.sha()
        verifier = RSA(public_key)

        logging.info('Verifying message: %s' % message)
        sha.update(message.encode('ascii'))

        digest = sha.hexdigest()
        logging.info('Digest: %s' % digest)
        logging.info('Used Signature: %s' % signature)
        logging.info(public_key)
        if verifier.verify_data(signature, digest.encode('ascii')):
            return True
        else:
            return False

    def sign_file(self, filename):
        sha = self.sha()

        try:
            logging.info('Signing file %s' % filename)
            with open(filename, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha.update(byte_block)
        except Exception as ex:
            logging.error(ex)
            logging.error('Can not open file %r' % filename)
            return False

        digest = sha.hexdigest()
        logging.info('Digest: %s' % digest)
        signature = self.signer.sign_data(digest.encode('ascii'))
        logging.info('Signature: %s' % signature)
        return signature

    def verify_file(self, signature, filename, public_key):
        sha = self.sha()
        verifier = RSA(public_key)

        try:
            logging.info('Verifying file %s' % filename)
            with open(filename, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha.update(byte_block)
        except Exception as ex:
            logging.error(ex)
            logging.error('Can not open file %r' % filename)
            return False

        digest = sha.hexdigest()
        logging.info('Digest: %s' % digest)
        logging.info('Used Signature: %s' % signature)
        if verifier.verify_data(signature, digest.encode('ascii')):
            logging.info('Authentic Message!')
            return True
        else:
            logging.info("Not authentic message!!!")
            return False
