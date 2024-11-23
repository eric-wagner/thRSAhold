# Threshold RSA Encryption Library

ThRSAhold is a compact Python library that implements a hybrid RSA threshold encryption scheme for arbitrary plaintext length. 

Threshold encryption is an asymmetric encryption scheme where a *public key* is used to encrypt a plaintext message. However, there exist no single *private key* to decrypt a ciphertext. Instead, the decryption requires the collaboration of at least *k* of private key share holders, where *k* and the total number of key share holders *l* is defined during key generation.

If the plaintext is too long for the RSA key size (2048 bit by default), thRSAhold uses an hybrid encryption scheme, where an AES key is generated and prepended to the plaintext. This AES key is used to encrypt the excess plaintext in GCM mode. All plaintexts are padded with PKCS#1 v1.5.

The implementation of the key generation, threshold RSA encryption and decryption, follows the description of threshold signatures in Victor Shoup's paper titled "Practical Threshold Signatures" [1].

One advantage of thRSAhold is that encryption can be performed by any standard RSA and AES implementation, which enable fast encryption through e.g., openssl. See the [README](https://github.com/eric-wagner/thRSAhold/blob/main/src/openssl/README.md) in the ```openssl``` directory on [GitHub](https://github.com/eric-wagner/thRSAhold) for a thRSAhold-compatible openssl implementation of the encryption procedure in C.

**Warning:** This implementation is not side-channel resilient or memory-safe and has not been audited. It should thus not be used for commercial applications! 

## Getting Started

The easiest way to getting started is to just download thRSAhold via pip:
```
pip install thRSAhold
```

Alternatively, you can also download the source code of thRSAhold on [GitHub](https://github.com/eric-wagner/thRSAhold). In that case make sure that `pycryptodome` is installed:

This library was tested with `pycryptodome` version 3.20.0.

## Example

A simple example of encrypting and decrypting a short message with thRSAhold. Note that privkeys should most likely be securely distributed to different entities, which locally compute the decryption shares that can then be verified and combined by anyone knowing the public key.

```
import thRSAhold

plaintext = b"A short test message."

k = 5 # threshold of required shares
l = 10 # amount of shares

pubkey, privkeys = thRSAhold.generate_key_shares(k, l)

ciphertext = pubkey.encrypt(plaintext)

shares = []
for i in range(k):
    s = privkeys[i].compute_share( ciphertext )
    shares.append(s)

for share in shares:
    pubkey.verify_zkp(share, ciphertext)

plaintext = pubkey.combine_shares(shares, ciphertext)

print( plaintext )
```

## Functionality

In the following, the functionalities of the different thRSAhold components are described in more detail.

### Key generation

To generate the *public encryption key* and the *private decryption key shares*, thRSAhold offers the ```generate_key_shares(k,l)``` function. The parameter *k* denotes how many *decryption shares* are required for decryption, and the parameter *l* denotes how many *private decryption key* shares exist. The function returns one ```PublicKey``` object and a list of *l* ```PrivateKey``` objects.

At this time, thRSAhold does not support distributed key generation.

### Class: PublicKey

> encrypt(plaintext)
> - plaintext -  the plaintext bytes to be encrypted
> - Returns: the encrypted plaintext (ciphertext)

> serialize(self)
> - Returns: a serialized string of the ```PublicKey``` object

> deserialize(cls, key)
> - key - a serialized ```PublicKey``` object
> - Returns: a ```PublicKey``` object

> to_file(self, path)
> - path - path of the file where the ```PublicKey``` object should be stored 

> from_file(cls, path)
> - path - path of the file where the ```PublicKey``` object is stored 
> - Returns: a PublicKey object

> to_pem_file(self, path)
> - path - path of the file where the ```PublicKey``` object should be stored in .pem format 

> to_der_file(self, path)
> - path - path of the file where the ```PublicKey``` object  object should be stored in .der format 
    
> verify_zkp(self, share, ciphertext)
> - share - a ```DecryptionShare``` object
> - ciphertext - the ciphertext
> - Returns: True if the decryption share is authentic, False otherwise

> combine_shares(self, shares, ciphertext)
> - shares - a least of at least *k* authentic ```DecryptionShare``` objects, each generated from a different ```PrivateKey```
> - ciphertext - the ciphertext
> - Returns: the plaintext


### Class: PrivateKey

> compute_share(self, ciphertext)
> - ciphertext - the ciphertext
> - Returns: a ```DecryptionShare``` object

> serialize(self)
> - Returns: a serialized string of the ```PrivateKey``` object

> deserialize(cls, key)
> - key - a serialized ```PrivateKey``` object
> - Returns: a ```PrivateKey``` object

> to_file(self, path)
> - path - path of the file where the ```PrivateKey``` object should be stored 

> from_file(cls, path)
> - path - path of the file where the ```PrivateKey``` object is stored 
> - Returns: a ```PrivateKey``` object

### Class: DecryptionShare

> serialize(self)
> - Returns: a serialized string of the ```DecryptionShare``` object

> deserialize(cls, key)
> - key - a serialized ```DecryptionShare``` object
> - Returns: a ```DecryptionShare``` object

> to_file(self, path)
> - path - path of the file where the ```DecryptionShare``` object should be stored 

> from_file(cls, path)
> - path - path of the file where the ```DecryptionShare``` object is stored 
> - Returns: a ```DecryptionShare``` object

## Contact

Eric Wagner - eric.wagner@fkie.fraunhofer.de

## References

[1] Shoup, V. Practical Threshold Signatures. In International Conference on
the Theory and Applications of Cryptographic Techniques (2000), Springer,
pp. 207–220.