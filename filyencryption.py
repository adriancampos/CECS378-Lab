import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac


def main():
    test_MyEncrypt_Decrypt()

    print()

    test_MyFileEncrypt_Decrypt()


def test_MyEncrypt_Decrypt():
    print("Testing encrypt(decrypt(\"Hello World!\"))")
    enc_key = os.urandom(32)
    hmac_key = os.urandom(32)

    plaintext = b"Hello World!"

    (tag, ct, iv) = MyEncrypt(plaintext, enc_key, hmac_key)

    print("ciphertext:", ct)
    print("tag:", tag)

    decryptedtext = MyDecrypt(ct, enc_key, hmac_key, iv, tag)

    print("result:", decryptedtext)
    print("Matches:", plaintext == decryptedtext)


TEST_FILENAME = "data/filetoencrypt.txt"


def test_MyFileEncrypt_Decrypt():
    (ciphertext, iv, tag, enc_key, hmac_key, ext) = test_MyFileEncrypt()
    test_MyFileDecrypt(iv, enc_key, hmac_key, tag, ext)


def test_MyFileEncrypt():
    print("Testing encryptfile(decryptfile(\"" + TEST_FILENAME + "\"))")
    (ciphertext, iv, tag, enc_key, hmac_key, ext) = MyFileEncrypt(TEST_FILENAME)
    return ciphertext, iv, tag, enc_key, hmac_key, ext


def test_MyFileDecrypt(iv, enc_key, hmac_key, tag, ext):
    MyFileDecrypt(TEST_FILENAME + ext, enc_key, hmac_key, iv, tag)


def MyEncrypt(message, enc_key, hmac_key):
    """
    Generates a 16 byte IV and encrypts the message using key and IV in AES CBC mode.
    :param message: 
    :param enc_key: 
    :param hmac_key: 
    :raises ValueError: if len(key) < 32
    :return: (tag, ciphertext, IV)
    """

    # ensure that len(key) >= 32
    if len(enc_key) < 32:
        raise ValueError("key must be at least 32 bytes long")

    # pad message
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message)

    padded_message += padder.finalize()

    # encrypt padded_message
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_message) + encryptor.finalize()

    # HMAC
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(ct)
    tag = h.finalize()

    return tag, ct, iv


def MyDecrypt(ciphertext, enc_key, hmac_key, iv, tag):
    """
    Decrypts ciphertext using key and iv in AES CBC mode.
    :param ciphertext:
    :param enc_key: 
    :param hmac_key: 
    :param iv:
    :param tag:
    :raises cryptography.exceptions.InvalidSignature: if tag does not match digest
    :return: plaintext
    """

    # HMAC verify
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    h.verify(tag)

    # decrypt ciphertext
    backend = default_backend()
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=backend)
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
    :return: (ciphertext, IV, HMAC tag, encryption key, HMAC key, file extension of new file)
    """

    enc_key = os.urandom(32)
    hmac_key = os.urandom(32)

    print("key:", enc_key)

    with open(filepath, 'rb') as file:
        # TODO The project description says that we must read the file as a string. That can cause potential problems when encrypting/decrypting raw bytes, depending on the encoding. Let's read it in binary mode unless told otherwise.
        contents = file.read()

        (tag, ciphertext, iv) = MyEncrypt(contents, enc_key, hmac_key)

    with open(filepath + ".encrypted", 'wb') as file:
        file.write(ciphertext)

    return ciphertext, iv, tag, enc_key, hmac_key, ".encrypted"


def MyFileDecrypt(filepath, enc_key, hmac_key, iv, tag):
    """
    Reads the file at filepath, decrypts the contents, and writes them to (filepath + ".decrypted").
    Can easily be modified to write the result to the original file if so desired.
    :param filepath: 
    :param enc_key: 
    :param hmac_key: 
    :param iv: 
    :param tag: 
    """
    with open(filepath, 'rb') as file:
        contents = file.read()

        plaintext = MyDecrypt(contents, enc_key, hmac_key, iv, tag)

    with open(filepath + ".decrypted", 'wb') as file:
        file.write(plaintext)


main()
