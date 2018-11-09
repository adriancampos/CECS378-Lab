import constants
import encryption
import json
import base64


def main():
    ensure_rsa_keys_exists()

    TEST_FILE = "data/filetoencrypt.txt"
    TEST_JSON = TEST_FILE + ".json"

    # Reads the test file, encrypts (but doesn't delete) it.
    encrypt_file(TEST_FILE, TEST_JSON)

    # Reads the encrypted json file, decrypts (but doesn't delete) it.
    decrypt_file(TEST_JSON, TEST_FILE + "_output.txt")


def ensure_rsa_keys_exists():
    try:
        priv_key = encryption.LoadRSAPrivateKey(constants.RSA_PRIVATEKEY_FILEPATH)
        pub_key = encryption.LoadRSAPublicKey(constants.RSA_PUBLICKEY_FILEPATH)

        print("RSA keys found")
    except (FileNotFoundError, ValueError):
        print("RSA keys not found. Creating...")

        (priv_key, pub_key) = encryption.GenerateRSAKey()

        encryption.WriteRSAPrivateKey(constants.RSA_PRIVATEKEY_FILEPATH, priv_key)
        encryption.WriteRSAPublicKey(constants.RSA_PUBLICKEY_FILEPATH, pub_key)

    print(priv_key)
    print(pub_key)


def base64ToString(b):
    return base64.encodestring(b).decode('ascii')


def stringToBase64(s):
    return base64.decodebytes(s.encode('ascii'))


def encrypt_file(infile, outfile):
    (RSACipher, ciphertext, iv, tag) = encryption.MyRSAEncrypt(infile,
                                                               constants.RSA_PUBLICKEY_FILEPATH)
    data = {
        "rsa": base64ToString(RSACipher),
        "ciphertext": base64ToString(ciphertext),
        "iv": base64ToString(iv),
        "tag": base64ToString(tag),
    }

    with open(outfile, "w") as file:
        json.dump(data, file)


def decrypt_file(infile, outfile):
    with open(infile, "r") as file:
        data = json.load(file)

    print(data['tag'])

    RSACipher = stringToBase64(data['rsa'])
    ciphertext = stringToBase64(data['ciphertext'])
    iv = stringToBase64(data['iv'])
    tag = stringToBase64(data['tag'])

    print(encryption.MyRSADecrypt(outfile, RSACipher, ciphertext, iv, tag,
                                  constants.RSA_PRIVATEKEY_FILEPATH))


main()
