import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def main():
    test_MyEncrypt_Decrypt()

    print()

    test_MyFileEncrypt_Decrypt()


def test_MyEncrypt_Decrypt():
    print("Testing encrypt(decrypt(\"Hello World!\"))")
    key = os.urandom(32)

    plaintext = b"Hello World!"

    (ct, iv) = MyEncrypt(plaintext, key)

    print("ciphertext:", ct)

    decryptedtext = MyDecrypt(ct, key, iv)

    print("result:", decryptedtext)
    print("Matches:", plaintext == decryptedtext)


TEST_FILENAME = "data/filetoencrypt.txt"


def test_MyFileEncrypt_Decrypt():
    (ciphertext, iv, key, ext) = test_MyFileEncrypt()
    test_MyFileDecrypt(iv, key, ext)


def test_MyFileEncrypt():
    print("Testing encryptfile(decryptfile(\"" + TEST_FILENAME + "\"))")
    (ciphertext, iv, key, ext) = MyFileEncrypt(TEST_FILENAME)
    return ciphertext, iv, key, ext


def test_MyFileDecrypt(iv, key, ext):
    MyFileDecrypt(TEST_FILENAME + ext, key, iv)


def MyEncrypt(message, key):
    """
    Generates a 16 byte IV and encrypts the message using key and IV in AES CBC mode.
    :param message: 
    :param key:
    :raises ValueError: if len(key) < 32
    :return: (ciphertext, IV)
    """

    # ensure that len(key) >= 32
    if len(key) < 32:
        raise ValueError("key must be at least 32 bytes long")

    # pad message
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message)

    padded_message += padder.finalize()

    # encrypt padded_message
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_message) + encryptor.finalize()

    return ct, iv


def MyDecrypt(ciphertext, key, iv):
    """
    Decrypts ciphertext using key and iv in AES CBC mode.
    :param ciphertext: 
    :param key: 
    :param iv: 
    :return: plaintext
    """

    # decrypt ciphertext
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decrypter = cipher.decryptor()
    padded_plaintext = decrypter.update(ciphertext) + decrypter.finalize()

    # unpad padded_plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext)
    plaintext += unpadder.finalize()

    return plaintext


def MyFileEncrypt(filepath):
    """
    Generates a 32 byte key. Reads the file at filepath, encrypts the contents, and writes them to (filepath + ".encrypted").
    Can easily be modified to write the result to the original file if so desired.
    :param filepath: 
    :return: (ciphertext, IV, key, file extension of new file)
    """

    key = os.urandom(32)

    print("key:", key)

    with open(filepath, 'rb') as file:
        # TODO The project description says that we must read the file as a string. That can cause potential problems when encrypting/decrypting raw bytes, depending on the encoding. Let's read it in binary mode unless told otherwise.
        contents = file.read()

        (ciphertext, iv) = MyEncrypt(contents, key)

    with open(filepath + ".encrypted", 'wb') as file:
        file.write(ciphertext)

    return ciphertext, iv, key, ".encrypted"


def MyFileDecrypt(filepath, key, iv):
    """
    Reads the file at filepath, decrypts the contents, and writes them to (filepath + ".decrypted").
    Can easily be modified to write the result to the original file if so desired.
    :param filepath: 
    :param key: 
    :param iv: 
    """
    with open(filepath, 'rb') as file:
        contents = file.read()

        plaintext = MyDecrypt(contents, key, iv)

    with open(filepath + ".decrypted", 'wb') as file:
        file.write(plaintext)


main()
