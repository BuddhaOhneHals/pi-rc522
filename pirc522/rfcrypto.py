# -*- coding: utf-8 -*-
#!/usr/bin/env python
import os
import hashlib
from base64 import b64encode, b64decode
from Crypto.Cipher import AES

#
# Add AES-128 CBC encryption functions for use with the
# RC-522 Library's read_card and write_card
# The MAX_PT_LEN takes into account th
# 543 bytes = 748 bytes after encryption (4bytes left over)
# 544 bytes = 768 bytes after encryption (too big)


BS = 16  # AES Block size is 16 bytes
SECURE_ITR = 400000  # Number of interations. More secure (slower bruting)
BASIC_ITR = 250000  # Number of interations. Less secure (faster bruting)
SALT_LEN = 32  # 32 byte (256 bit) random salt length for key generation
MAX_PT_LEN = 495  # Largest plaintext which will fit on a 1k card with a 32 byte hash

pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1])]


class Cipher:

    padded = ""

    def __init__(self, password, ic=SECURE_ITR, salt=None):
        if salt is None:
            self.salt = os.urandom(SALT_LEN)
        else:
            self.salt = salt
        self.key, self.salt = self.gen_key(password, ic)

    def gen_key(self, pw, iteration_count=SECURE_ITR):

        k = hashlib.pbkdf2_hmac('sha256',
                                b'%s' % pw,
                                b'%s' % self.salt,
                                iteration_count)
        return (k, self.salt)

    def encrypt(self, plaintext):
        plaintext = pad(plaintext)
        self.padded = plaintext
        os.GRND_RANDOM = True  # Switch to using /dev/random
        iv = os.urandom(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(plaintext))

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))

    def hmac(self, data_str, key=None):
        if key is None:
            key = b64encode(os.urandom(SALT_LEN))
        exp_key, exp_salt = self.gen_key(key, SECURE_ITR)
        macer = hashlib.sha256()
        macer.update(data_str + exp_key)
        khmac = macer.digest()
        return (key, khmac)

    def random(self, num_bytes):
        print "getting %d bytes" % num_bytes
        os.GRND_RANDOM = True  # Switch to using /dev/random
        block = os.urandom(num_bytes)
        return block
