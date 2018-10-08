# CSULB CECS378 Lab

https://tradlab.me

## File Encryption
Using Python [Cryptography](https://cryptography.io/en/latest/hazmat/primitives/), these modules encrypt and decrypt a message or file.
### Part 1
`MyEncrypt(message, enc_key, hmac_key)` generates a 16 byte IV and encrypts the message using key and IV in AES CBC mode.

`MyDecrypt(ciphertext, enc_key, hmac_key, iv, tag)` decrypts ciphertext using a given key and iv in AES CBC mode.

`MyFileEncrypt(filepath)` generates a 32 byte key. Reads the file at filepath, encrypts the contents, and returns them.

`MyFileDecrypt(filepath, enc_key, hmac_key, iv, tag)` decrypts the ciphertext and writes the plaintext to a file at filepath. Also returns the plaintext.

#### Try it out
Running test_MyEncrypt_Decrypt() will will encrypt some text with random keys, decrypt it, and print the results.
rites the contents to a new `.encrypted` file, reads that file's contents, and uses the key to decrypt its contents before writing them to a `.decrypted` file.
