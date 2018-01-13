import pickle
import rfcrypto
from base64 import b64encode
# Adds support for AES encryption when dealing with MiFare Classic 1k cards
# Also adds an EncryptionException class which can be used by the consumer
# to gracefully handle exceptions.
class EncryptionException(Exception):
    pass
class RFIDException(Exception):
    pass

class RFIDUtil(object):
    rfid = None
    method = None
    key = None
    uid = None
    last_auth = None

    debug = False
    verbose = False  # A second level to verbosity to print full details

    def __init__(self, rfid):
        self.rfid = rfid

    def block_addr(self, sector, block):
        """
        Returns block address of spec. block in spec. sector.
        """
        return sector * 4 + block

    def sector_string(self, block_address):
        """
        Returns sector and it's block representation of block address, e.g.
        S01B03 for sector trailer in second sector.
        """
        return "S" + str((block_address - (block_address % 4)) / 4) + "B" + str(block_address % 4)

    def set_tag(self, uid):
        """
        Sets tag for further operations.
        Calls deauth() if card is already set.
        Calls RFID select_tag().
        Returns called select_tag() error state.
        """
        if self.debug:
            print("Selecting UID " + str(uid))

        if self.uid != None:
            self.deauth()

        self.uid = uid
        return self.rfid.select_tag(uid)

    def auth(self, auth_method, key):
        """
        Sets authentication info for current tag
        """
        self.method = auth_method
        self.key = key

        if self.debug:
            print("Changing used auth key to " + str(key) + " using method " + ("A" if auth_method == self.rfid.auth_a else "B"))

    def deauth(self):
        """
        Resets authentication info. Calls stop_crypto() if RFID is in auth state
        """
        self.method = None
        self.key = None
        self.last_auth = None

        if self.debug:
            print("Changing auth key and method to None")

        if self.rfid.authed:
            self.rfid.stop_crypto()
            if self.debug:
                print("Stopping crypto1")

    def is_tag_set_auth(self):
        return (self.uid != None) and (self.key != None) and (self.method != None)

    def do_auth(self, block_address, force=False):
        """
        Calls RFID card_auth() with saved auth information if needed.
        Returns error state from method call.
        """
        auth_data = (block_address, self.method, self.key, self.uid)
        if (self.last_auth != auth_data) or force:
            if self.debug:
                print("Calling card_auth on UID " + str(self.uid))

            self.last_auth = auth_data
            return self.rfid.card_auth(self.method, block_address, self.key, self.uid)
        else:
            if self.debug:
                print("Not calling card_auth - already authed")
            return False

    def write_trailer(self, sector, key_a=(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF), auth_bits=(0xFF, 0x07, 0x80),
                      user_data=0x69, key_b=(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)):
        """
        Writes sector trailer of specified sector. Tag and auth must be set - does auth.
        If value is None, value of byte is kept.
        Returns error state.
        """
        addr = self.block_addr(sector, 3)
        return self.rewrite(addr, key_a[:6] + auth_bits[:3] + (user_data, ) + key_b[:6])

    def rewrite(self, block_address, new_bytes):
        """
        Rewrites block with new bytes, keeping the old ones if None is passed. Tag and auth must be set - does auth.
        Returns error state.
        """
        if not self.is_tag_set_auth():
            return True

        error = self.do_auth(block_address)
        if not error:
            (error, data) = self.rfid.read(block_address)
            if not error:
                for i in range(len(new_bytes)):
                    if new_bytes[i] != None:
                        if self.debug and self.verbose:
                            print("Changing pos " + str(i) + " with current value " + str(data[i]) + " to " + str(new_bytes[i]))

                        data[i] = new_bytes[i]

                error = self.rfid.write(block_address, data)
                if self.debug and self.verbose:
                    print("Writing " + str(data) + " to " + self.sector_string(block_address))

        return error

    def read_out(self, block_address):
        """
        Reads contents of block. Tag and auth must be set Does block auth if required.
        """
        if not self.is_tag_set_auth():
            return (True, None)

        error = self.do_auth(block_address)
        if not error:
            (error, data) = self.rfid.read(block_address)
            if self.debug and self.verbose:
                print(self.sector_string(block_address) + ": " + str(data))
            return (None, data)
        else:
            if self.debug:
                print("Error on " + self.sector_string(block_address))
            return (error, None)

    def get_access_bits(self, c1, c2, c3):
        """
        Calculates the access bits for a sector trailer based on their access conditions
        c1, c2, c3, c4 are 4 items tuples containing the values for each block
        returns the 3 bytes for the sector trailer
        """
        byte_6 = ((~c2[3] & 1) << 7) + ((~c2[2] & 1) << 6) + ((~c2[1] & 1) << 5) + ((~c2[0] & 1) << 4) + \
                 ((~c1[3] & 1) << 3) + ((~c1[2] & 1) << 2) + ((~c1[1] & 1) << 1) + (~c1[0] & 1)
        byte_7 = ((c1[3] & 1) << 7) + ((c1[2] & 1) << 6) + ((c1[1] & 1) << 5) + ((c1[0] & 1) << 4) + \
                 ((~c3[3] & 1) << 3) + ((~c3[2] & 1) << 2) + ((~c3[1] & 1) << 1) + (~c3[0] & 1)
        byte_8 = ((c3[3] & 1) << 7) + ((c3[2] & 1) << 6) + ((c3[1] & 1) << 5) + ((c3[0] & 1) << 4) + \
                 ((c2[3] & 1) << 3) + ((c2[2] & 1) << 2) + ((c2[1] & 1) << 1) + (c2[0] & 1)
        return byte_6, byte_7, byte_8

    def dump(self, sectors=16):
        buff = []
        for i in range(sectors * 4):
            (error, block) = self.read_out(i)
            if not error:
                buff.append(block)
            else:
                raise RFIDException(error)
        if self.debug and self.verbose:
            print buff
        return buff

    # Will intelligently load data onto a card
    # If the data is an object, it will be serialized with pickle.
    # If the data is a string it will not be changed.
    # After this, data length will be verified to fit
    # Encrypted Free Space.EncryptionException()
    def load(self, data, encrypt = True, aes_key = None):
        if encrypt:
            # try converting non-string data to string via serialization
            if not isinstance(data, type("string")):
                try:
                    data = pickle.dumps(data)
                except Exception:
                    raise EncryptionException("Data could not be converted")
            if aes_key is None:
                raise EncryptionException("Missing aes_key parameter")

            cipher = rfcrypto.Cipher(aes_key)

            # Verify the data length is less than the max
            if len(data) > rfcrypto.MAX_PT_LEN:
                raise EncryptionException("Oversized Data Object")

            # The resulting string is then encrypted.
            dat_blk = cipher.encrypt(data)  # b64encoded rep of the cipher
            if self.debug:
                print "Plain Text: %s" % data
                print "Cipher initialized with password: %s" % aes_key
                print "PBKDF2 key: %s" % b64encode(cipher.key)
                print "Salt: %s" % b64encode(cipher.salt)
                print "Length of cipher: %d" % (len(dat_blk))
                print "Cipher: %s" % dat_blk
                print "Verifying decryption"
                dec = cipher.decrypt(dat_blk)
                if dec == data:
                    print "Decryption verified"
                else:
                    print data
                    print "------" * 5
                    print dec
                    raise EncryptionException("Decryption Verification Failed")
            (h_key, dat_hash) = cipher.hmac(dat_blk)  # Hash the cipher + rand key
            dat_bytes = [ord(c) for c in dat_blk]
            if self.debug:
                print "Data Hash"
                print b64encode(dat_hash)
            data_buff = self.chunk_data(dat_bytes, 16)

        else:
            data_buff = data

        if self.debug and self.verbose:
            print "\nData Buffer:"
            print data_buff
            print "\n"
        block_addr = 1
        for i in range(0, len(data_buff)):
            block = data_buff[i]
            if (block_addr % 4 == 3):
                # These are the sector trailers, we don't want to overwrite
                block_addr += 1
            self.rewrite(block_addr, block)
            if self.debug and self.verbose:
                print "Wrote Block to block address %d" % block_addr
            block_addr += 1
        if encrypt:
            # To decrypt the tags, the client will need the salt and the
            #length of the cipher
            print b64encode(cipher.salt)
            return (len(dat_blk), cipher.salt)

    def dump_decrypted(self, cipher_len, tag_pass, tag_salt):
        buff = self.dump()
        enc_bytes = []
        for i in range(1, len(buff)):
            block = buff[i]
            if (i % 4 != 3):
                # Moves the bytes into a single list
                for b in block:
                    enc_bytes.append(chr(b))
        enc_str = "".join(enc_bytes[0:cipher_len])
        cipher = rfcrypto.Cipher(tag_pass, rfcrypto.SECURE_ITR, tag_salt)
        if self.debug:
            print "Recovered b64 encoded cipher text\n%s" % enc_str
            print "Initialized with password: %s" % tag_pass
            print "Initialized with salt: %s" % b64encode(tag_salt)
            print "PBKDF2 key: %s" % b64encode(cipher.key)
            print "Cipher Salt: %s" % b64encode(cipher.salt)
            print "Length of cipher: %d" % (len(enc_str))
            print "Verifying decryption"
            dec = cipher.decrypt(enc_str)
            if dec == "testing":
                print "It WORKED"
            else:
                print "FAILURE"
        # Decrpyt the data using the provided key
        data = cipher.decrypt(enc_str)
        if self.debug:
            print "Data read:"
            print data
            print "\n"
        return data

    def chunk_data(self, lst, chnk_sz):
        out = []
        for i in range(0, len(lst), chnk_sz):
            out.append(lst[i:i + chnk_sz])
        return out
