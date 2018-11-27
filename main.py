import argparse
import constants
import encryption
import json
import base64
from os import walk, path, remove


def test():
    ensure_rsa_keys_exists()

    TEST_FILE = "data/filetoencrypt.txt"
    TEST_JSON = TEST_FILE + ".json"

    # Reads the test file, encrypts (but doesn't delete) it.
    encrypt_file(TEST_FILE, TEST_JSON)

    # Reads the encrypted json file, decrypts (but doesn't delete) it.
    decrypt_file(TEST_JSON, TEST_FILE + "_output.txt")

    # For now, just remove one of these to see it work. I'll eventually add command line args to select
    encrypt_all_files(constants.ROOT_FOLDER)
    decrypt_all_files(constants.ROOT_FOLDER)


def ui():
    parser = argparse.ArgumentParser(description='TRAD\'s File Encryption.')  # TODO: Finish the description

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', action="store_true",
                       help='Encrypt the specified file(s)')

    group.add_argument('-d', '--decrypt', action="store_true",
                       help='Decrypt the specified files')

    parser.add_argument('path', type=lambda x: verify_path(parser, x), default=constants.ROOT_FOLDER,
                        help='either a single file or the root directory to traverse (default: "' + constants.ROOT_FOLDER + '")')

    parser.add_argument('--key-private', default=constants.RSA_PRIVATEKEY_FILEPATH,
                        help='Path of private RSA key. If one doesn\'t exist here it will be created. (default: "' + constants.RSA_PRIVATEKEY_FILEPATH + '")')
    parser.add_argument('--key-public', default=constants.RSA_PUBLICKEY_FILEPATH,
                        help='Path of public RSA key. If one doesn\'t exist here it will be created. (default: "' + constants.RSA_PUBLICKEY_FILEPATH + '")')

    args = parser.parse_args()

    # Set up arguments
    rootdir = args.path
    constants.RSA_PRIVATEKEY_FILEPATH = args.key_private  # TODO I shouldn't be changing constants. Need to rework methods to include an optional parameter
    constants.RSA_PUBLICKEY_FILEPATH = args.key_public

    # Perform encryption/decryption
    ensure_rsa_keys_exists()

    if path.isdir(rootdir):
        if args.encrypt:
            encrypt_all_files(rootdir=rootdir)
        if args.decrypt:
            decrypt_all_files(rootdir=rootdir)
    else:  # TODO: Finish single file encryption/decryption
        if args.encrypt:
            encrypt_file()
        if args.decrypt:
            decrypt_file()


def verify_path(parser, arg):
    if not path.exists(arg):
        parser.error("The path %s does not exist" % arg)
    else:
        return path.abspath(arg)


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


def encrypt_all_files(rootdir):
    for dirName, subdirList, fileList in walk(rootdir):
        for file in fileList:
            try:
                filePath = path.join(dirName, file)
                encrypt_file(filePath, filePath + constants.ENCRYPTED_EXTENSION)

                # Exclude public key
                if path.abspath(filePath) == path.abspath(constants.RSA_PUBLICKEY_FILEPATH):
                    break

                # Exclude private key
                if path.abspath(filePath) == path.abspath(constants.RSA_PRIVATEKEY_FILEPATH):
                    break

                # Executable will be excluded by default because it's running

                remove(filePath)

            except Exception as e:  # TODO Tighten exception
                # Don't kill the whole walk on failure
                print(e)


def decrypt_all_files(rootdir):
    for dirName, subdirList, fileList in walk(rootdir):
        for file in fileList:

            try:
                # Only touch files that we've encrypted
                if path.splitext(file)[1] == constants.ENCRYPTED_EXTENSION:
                    filePath = path.join(dirName, file)
                    decrypt_file(filePath,
                                 path.splitext(filePath)[0])

                    remove(filePath)

            except Exception as e:  # TODO Tighten exception
                # Don't kill the whole walk on failure
                print(e)


ui()
