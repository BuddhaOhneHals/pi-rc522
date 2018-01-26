# -*- coding: utf-8 -*-
import time
from pirc522 import RFID


DBNAME = 'crypto_station.db'
rdr = RFID()
util = rdr.util()
util.debug = True
PASSWORD = "d3aDB33f"

while True:
    # Wait for tag
    rdr.wait_for_tag()

    # Request tag
    (error, data) = rdr.request()
    if not error:
        print("\nDetected")

        (error, uid) = rdr.anticoll()
        if not error:
            print("Setting tag")
            util.set_tag(uid)
            print("\nAuthorizing")
            #util.auth(rdr.auth_a, [0x12, 0x34, 0x56, 0x78, 0x96, 0x92])
            util.auth(rdr.auth_b, [0xFF,0xFF,0xFF,0xFF,0xFF,0xFF])
            # uses the encrypted load function to write a secure card
            m1 = {
                "sku":"000000000000",
                "cid":"xxxxxxxxxxxxxx",
                "ocode":"aaaaaaaaaaaa",
                "dcode":"xxxxxxxxxx",
                "wght":0.0,
                "checker_id":"xxxxxxxxxx"
            }
            (cipher_len, salt) = util.load(m1, True, aes_key = PASSWORD)

            print "Encrypted Data with password and wrote to tag"
            print("\nDeauthorizing")
            util.deauth()
            raw_input("Remove tag and press enter")
            time.sleep(1)
