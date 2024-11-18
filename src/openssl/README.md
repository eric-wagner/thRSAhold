This directory contains a prototypical openssl implementation (in C) of thRSAhold-compatible encryption. 

If thRSAhold has been installed, ```generate_keys.py``` generates the keys the public encryption key (also exported in .pem format) and the private decryption keys shares.

```thRSAhold.h``` then offers a simple abstraction of the openssl EVP functions that implement the hybrid encryption as used by thRSAhold. The implementation of this encryption can be found in ```thRSAhold.c``` (only a prototype, error handling can be improved).

In ```main.c``` (which can be compiled by calling ```make```), ```thRSAhold.h``` in included to encrypt a basic plaintext (only containing 'a's) with the public key stated in the ```keys``` directory and write the corresponding ciphertext to the file ```ciphertext```.

Calling ```decrypt.py``` loads this ciphertext and the first 5 private keys shares to threshold-decrypt it in Python.