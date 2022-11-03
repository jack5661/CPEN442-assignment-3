from pydoc import plain
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from hashlib import sha256
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

class IntegrityError(Exception):
    pass

class Protocol:
    ALICE_MSG = "Im Alice"
    BOB_MSG   = "Im Bob"
    NONCE_LENGTH = 16
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self, secret):
        self._key = None
        self._nonce_a = None
        self._nonce_b = None
        self._shared_nonce = (15).to_bytes(16, 'little')
        padder = padding.PKCS7(128).padder()
        padded_secret = padder.update(secret.encode()) + padder.finalize()
        self._shared_key = padded_secret
        self._dh_g = 2
        self._dh_p = None
        self._dh_private_key = None
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        # generate random nonce
        self._nonce_a = os.urandom(self.NONCE_LENGTH)
        # DH parameters
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        p = parameters.parameter_numbers().p
        self._dh_p = p
        return self.ALICE_MSG.encode() + self._nonce_a + p.to_bytes(256, 'little')


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        # Check initiation message
        if self.ALICE_MSG.encode() in message and len(message) == len(self.ALICE_MSG.encode()) + self.NONCE_LENGTH + 256:
            return True
        else:
            # Check for constants
            cipher = Cipher(algorithms.AES(self._shared_key), modes.CTR(self._shared_nonce))
            decryptor = cipher.decryptor()
            try:
                decrypted_msg = decryptor.update(message[:-self.NONCE_LENGTH])
                if decrypted_msg[self.NONCE_LENGTH:self.NONCE_LENGTH + len(self.BOB_MSG)] == self.BOB_MSG.encode():
                    return True
            except:
                pass
            try:
                decryptor = cipher.decryptor()
                decrypted_msg = decryptor.update(message)
                return decrypted_msg[:len(self.ALICE_MSG)] == self.ALICE_MSG.encode()
            except:
                return False


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        # First message
        next_msg = b""
        cipher = Cipher(algorithms.AES(self._shared_key), modes.CTR(self._shared_nonce))
        if self.ALICE_MSG.encode() in message:
            # Read challenge from Alice
            nonce_a = message[len(self.ALICE_MSG):len(self.ALICE_MSG) + self.NONCE_LENGTH]
            self._nonce_a = nonce_a
            # Read p from Alice
            p = int.from_bytes(message[-256:], 'little')
            self._dh_p = p
            # Generate challenge
            nonce_b = os.urandom(self.NONCE_LENGTH)
            self._nonce_b = nonce_b
            # Prepare session key establishment
            pn = dh.DHParameterNumbers(self._dh_p, self._dh_g)
            parameters_bob = pn.parameters()
            private_key = parameters_bob.generate_private_key()
            b = private_key.public_key().public_numbers().y
            self._dh_private_key = private_key
            encryptor = cipher.encryptor()
            next_msg = encryptor.update(nonce_a + self.BOB_MSG.encode() + b.to_bytes(256, 'little')) + nonce_b
        else:
            cipher = Cipher(algorithms.AES(self._shared_key), modes.CTR(self._shared_nonce))
            # Determine if second or third msg by decrypting
            second = False
            third = False
            try:
                decryptor = cipher.decryptor()
                decrypted_msg = decryptor.update(message[:-self.NONCE_LENGTH])
                if decrypted_msg[self.NONCE_LENGTH:self.NONCE_LENGTH + len(self.BOB_MSG)] == self.BOB_MSG.encode():
                    second = True
            except:
                pass
            try:
                decryptor = cipher.decryptor()
                decrypted_msg = decryptor.update(message)
                if decrypted_msg[:len(self.ALICE_MSG)] == self.ALICE_MSG.encode():
                    third = True
            except:
                pass
            if second:
                # Read challenge from Bob
                nonce_b = message[-self.NONCE_LENGTH:]
                self._nonce_b = nonce_b
                message = message[:-self.NONCE_LENGTH]
                # Check challenge was computed successfully
                cipher = Cipher(algorithms.AES(self._shared_key), modes.CTR(self._shared_nonce))
                decryptor = cipher.decryptor()
                decrypted_msg = decryptor.update(message)
                if decrypted_msg[:self.NONCE_LENGTH] != self._nonce_a:
                    raise Exception("Error in message format")
                decrypted_msg = decrypted_msg[self.NONCE_LENGTH:]
                if decrypted_msg[:len(self.BOB_MSG)] != self.BOB_MSG.encode():
                    raise Exception("Error in message format")
                decrypted_msg = decrypted_msg[len(self.BOB_MSG):]
                b = int.from_bytes(decrypted_msg, 'little')

                # Prepare session key establishment
                pn = dh.DHParameterNumbers(self._dh_p, self._dh_g)
                parameters_alice = pn.parameters()
                self._dh_private_key = parameters_alice.generate_private_key()
                peer_public_number = dh.DHPublicNumbers(b, pn)
                a = self._dh_private_key.public_key().public_numbers().y
                session_key = self._dh_private_key.exchange(peer_public_number.public_key())

                encryptor = cipher.encryptor()
                next_msg = encryptor.update(self.ALICE_MSG.encode() + nonce_b + a.to_bytes(256, 'little'))
                
                decryptor = cipher.decryptor()

                self.SetSessionKey(session_key)
            elif third:
                # Check challenge was computed successfully
                cipher = Cipher(algorithms.AES(self._shared_key), modes.CTR(self._shared_nonce))
                decryptor = cipher.decryptor()
                decrypted_msg = decryptor.update(message)
                if decrypted_msg[:len(self.ALICE_MSG)] != self.ALICE_MSG.encode():
                    raise Exception("Error in message format")
                decrypted_msg = decrypted_msg[len(self.ALICE_MSG):]
                if decrypted_msg[:self.NONCE_LENGTH] != self._nonce_b:
                    raise Exception("Error in message format")
                decrypted_msg = decrypted_msg[self.NONCE_LENGTH:]
                # Session Key establishment
                a = int.from_bytes(decrypted_msg, 'little')
                pn = dh.DHParameterNumbers(self._dh_p, self._dh_g)
                peer_public_number = dh.DHPublicNumbers(a, pn)
                session_key = self._dh_private_key.exchange(peer_public_number.public_key())

                self.SetSessionKey(session_key)    

        return next_msg
        


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        key = sha256(key).digest()
        self._key = key
        print(key)
        self._cipher = Cipher(algorithms.AES(key), modes.CTR(self._shared_nonce))


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        if self._key:
            encryptor = self._cipher.encryptor()
            cipher_text = encryptor.update(plain_text.encode()) + encryptor.finalize() + sha256(plain_text.encode() + self._key).digest()
        else:
            cipher_text = plain_text.encode()
        return cipher_text 


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        # figure out how to split message
        if self._key:
            length_of_hash = 32
            hash = cipher_text[-length_of_hash:]
            decryptor = self._cipher.decryptor()
            plain_text = (decryptor.update(cipher_text[:-length_of_hash]) + decryptor.finalize()).decode()
            computed_hash = sha256(plain_text.encode() + self._key).digest()
            if hash != computed_hash:
                raise IntegrityError("integrity issue")
        else:
            plain_text = cipher_text.decode()
        return plain_text
    

    def keySet(self):
        return self._key != None
