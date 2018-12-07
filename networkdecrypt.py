from fileutils import *
import requests

import base64

if check_public_key_exists():
    if not check_private_key_exists():
        # We don't have the private key. Ask the server, save it, then decrypt.
        print("Private key not found. Asking the server.")
        with open(constants.RSA_PUBLICKEY_FILEPATH, "rb") as key_file:
            pubkey = base64.b64encode(key_file.read()).decode('utf-8')

        print(constants.NETWORK_HOST + constants.NETWORK_ROUTE + "/" + pubkey)

        r = requests.get(constants.NETWORK_HOST + constants.NETWORK_ROUTE + "/" + pubkey)

        try:
            privkey = base64.b64decode(r.json()[0]['privkey'])

            with open(constants.RSA_PRIVATEKEY_FILEPATH, 'wb') as key_file:
                key_file.write(privkey)

        except:  # TODO Figure out which exceptions I actually want to catch
            raise Exception("Couldn't read key from server")  # TODO Raise a more helpful exception

    decrypt_all_files(constants.ROOT_FOLDER)
else:
    print("Public key not found!")
