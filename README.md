# CSULB CECS378 Lab

https://tradlab.me

## File Encryption
Using Python [Cryptography](https://cryptography.io/en/latest/hazmat/primitives/), these modules encrypt and decrypt a message or file.
### Part 1
`MyEncrypt(message, enc_key, hmac_key)` generates a 16 byte IV and encrypts the message using key and IV in AES CBC mode.

`MyDecrypt(ciphertext, enc_key, hmac_key, iv, tag)` decrypts ciphertext using a given key and iv in AES CBC mode.

`MyFileEncrypt(filepath)` generates a 32 byte key. Reads the file at filepath, encrypts the contents, and writes them to (filepath + ".encrypted"). Can be modified to write the result to the original file if so desired.

`MyFileDecrypt(filepath, enc_key, hmac_key, iv, tag)` reads the file at filepath, decrypts the contents, and writes them to (filepath + ".decrypted"). Can easily be modified to write the result to the original file if so desired.

#### Try it out
Running main() will run `test_MyEncrypt_Decrypt()` and `test_MyFileEncrypt_Decrypt()`.

`test_MyEncrypt_Decrypt` encrypts "Hello World!" with a random key, decrypts it, prints the ciphertext and decrypted text, and tests to ensure that the decrypted plaintext matches the original plaintext. 

`test_MyFileEncrypt_Decrypt` generates a random key, reads in a file specified by `TEST_FILENAME`, encrypts and writes the contents to a new `.encrypted` file, reads that file's contents, and uses the key to decrypt its contents before writing them to a `.decrypted` file.


To see it in action, place some text into `data/filetoencrypt.txt`. The first few paragraphs of [alice.txt](http://www.umich.edu/~umfandsf/other/ebooks/alice30.txt) are provided. After running the program, two new files should appear: `filetoencrypt.txt.encrypted` and `filetoencrypt.txt.encrypted.decrypted` (please do not save these to version control!). The encrypted file should be unreadable and the decrypted file should exactly match the original file. You may also try this with any binary file (remember to change `TEST_FILENAME`!)
