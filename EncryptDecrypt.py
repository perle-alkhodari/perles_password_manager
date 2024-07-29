import os
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import hashlib

SALT = b'\xfcv\x8f\x81\x03\xd0\x83YS]\xeb\x0c\xdb\xcd\x88x\xd7\xbdh0\xf7\xc3&\xa7\x8ap\x12\xf1\xddQ\\\x81'


class EncryptDecrypt:

    def __init__(self, password, file_path):
        self.key = PBKDF2(password, SALT, dkLen=32)
        self.file = file_path

    def overwrite_with(self, new_data):
        cipher = AES.new(self.key, AES.MODE_CBC)
        ciphered_message = cipher.encrypt(pad(new_data, AES.block_size))
        with open(self.file, 'wb') as binary_file:
            binary_file.write(cipher.iv)
            binary_file.write(ciphered_message)

    def encrypt_to_file(self, message):

        encoded_message = message.encode("utf-8") + self.decrypt_from_file().encode("utf-8") \
            if os.path.exists(self.file) else message.encode("utf-8")
        self.overwrite_with(encoded_message)

    def decrypt_from_file(self):

        with open(self.file, 'rb') as binary_file:
            iv = binary_file.read(16)
            data = binary_file.read()

        cipher_decrypt = AES.new(self.key, AES.MODE_CBC, iv=iv)
        message = unpad(cipher_decrypt.decrypt(data), AES.block_size)
        return message.decode("utf-8")

    def remove_from_file(self, message):

        if message in self.decrypt_from_file():
            new_data = self.decrypt_from_file().replace(message, "").encode("utf-8")
            self.overwrite_with(new_data)

    def replace_from_file(self, message_to_replace, replacement):

        if message_to_replace in self.decrypt_from_file():
            new_data = self.decrypt_from_file().replace(message_to_replace, replacement)
            self.overwrite_with(new_data)


class Hash:

    @staticmethod
    def hash_password(password):
        password_bytes = password.encode('utf-8')
        hash_object = hashlib.sha256(password_bytes)
        return hash_object.hexdigest()
