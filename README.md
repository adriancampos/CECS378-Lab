# CSULB CECS378 Lab

https://tradlab.me

## File Encryption
Using Python [Cryptography](https://cryptography.io/en/latest/hazmat/primitives/), these modules encrypt and decrypt a message or file.

File contents are encrypted with AES-256 in CBC mode and a randomly generated key. The encryption and HMAC keys are encrypted with RSA. Along with the ciphertext of the file contents, they are stored on the disk and the original file is removed.  

### Try it out
Grab the executables from the [releases](https://github.com/adriancampos/CECS378-Lab/releases/latest) page.

encrypt.exe generates a public/private keypair, encrypts files (recursively) within ./dangerzone.

decrypt.exe reads the public/private keypair, decrypts files (recursively) within ./dangerzone.


### Building the executables
`pyinstaller --onefile decrypt.py` and `pyinstaller --onefile encrypt.py` generate executables in ./dist/
