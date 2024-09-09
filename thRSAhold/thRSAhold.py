import random
import math
import hashlib
import os
import json
import binascii
from copy import deepcopy
from Crypto.Cipher import AES
from Crypto.Util import number
from Crypto.PublicKey import RSA

def egcd(a, b):
    
    t0, t1, s0, s1 = 0, 1, 1, 0
    
    while a != 0:
        (q, a), b = divmod(b, a), a
        s0, s1 = s1, s0 - q * s1
        t0, t1 = t1, t0 - q * t1
    
    return b, t0, s0

class PublicKey:

    def __init__(self, n, e, v, V_i, l, k):
        self.n = n
        self.e = e
        self.v = v
        self.V_i = V_i.copy()
        self.l = l
        self.k = k
        
        self.AES_KEYSIZE = 32 # bytes
        self.rsa_ct_len = self.n.bit_length() // 8

    @classmethod
    def from_file(cls, path):
        with open(path, "rb") as f:
            serialized_key = f.read()
        return cls.deserialize(serialized_key)
    
    def to_pem_file(self, path):
        publicKey = RSA.construct((self.n, self.e))
        publicKeyPem = publicKey.exportKey() # export in X.509/SPKI format

        with open(path, "wb") as f:
            f.write(publicKeyPem)

    def to_file(self, path):
        content = self.serialize()
        with open(path, "wb") as f:
            f.write(content)

    @classmethod
    def deserialize(cls, serialized_key):
        json_key = json.loads(serialized_key)
        return cls(json_key["n"], json_key["e"], json_key["v"], json_key["V_i"], json_key["l"], json_key["k"])

    def serialize(self):
        json_key = { "n":self.n, "e":self.e, "v":self.v, "V_i":self.V_i, "l":self.l, "k":self.k }
        return json.dumps(json_key).encode('utf-8')

    def encrypt(self, plaintext):
                
        if len(plaintext) < self.rsa_ct_len:
            padding_len = max(self.rsa_ct_len - len(plaintext), 3)
        else:
            padding_len = 3
        
        padding = b"\x00\x02" +  b"\xff" * (padding_len - 3) + b"\x00"
                
        assert(len(plaintext) + len(padding) >= self.rsa_ct_len)
        
        if( len(padding) + len(plaintext) == self.rsa_ct_len ):
            
            padded_pt = bytes( list(padding) + list(plaintext) )
            pt = int.from_bytes(padded_pt, 'big')
            ct = pow(pt, self.e, self.n)
            ct = ct.to_bytes(self.rsa_ct_len, 'big')
                        
            return ct
        
        #generate aes key and append to start of plaintext, fill asymmetrically encrypted part with start plaintext
        aes_key = os.urandom(self.AES_KEYSIZE)
        pt = b"".join( [padding, aes_key, plaintext[:self.rsa_ct_len-self.AES_KEYSIZE-padding_len] ])
               
        ct = pow( int.from_bytes(pt, 'big'), self.e, self.n )
        ct = ct.to_bytes(self.rsa_ct_len, 'big')

        aes = AES.new(aes_key, AES.MODE_GCM, nonce=b"\0" * 16)
        added_ct, tag = aes.encrypt_and_digest(plaintext[self.rsa_ct_len-self.AES_KEYSIZE-padding_len:])
        final_ct = bytes(list(ct) + list(added_ct) + list(tag))
                        
        return final_ct


    def verify_zkp(self, share, ciphertext):

        if( len(ciphertext) > self.rsa_ct_len ):
            x = int.from_bytes(ciphertext[:self.rsa_ct_len], 'big')
        else:
            x = int.from_bytes(ciphertext, 'big')

        delta = math.factorial(self.l)
        x_tilde = x_tilde = pow( x, 4*delta, self.n ) 
        v_i = self.V_i[share.i-1]

        m = hashlib.sha3_256()
        h_input = self.v.to_bytes((self.v.bit_length() + 7) // 8, 'big')
        h_input += x_tilde.to_bytes((x_tilde.bit_length() + 7) // 8, 'big')
        h_input += v_i.to_bytes((v_i.bit_length() + 7) // 8, 'big')
        x_sq = pow(share.x_i,2)
        h_input += x_sq.to_bytes((x_sq.bit_length() + 7) // 8, 'big')

        v1 = pow(self.v, share.z, self.n) * pow( pow(v_i,-1, self.n), share.c, self.n) % self.n
        h_input += v1.to_bytes((v1.bit_length() + 7) // 8, 'big')
        
        x1 = pow(x_tilde, share.z, self.n) * pow( pow(share.x_i,-1, self.n),2*share.c, self.n) % self.n
        h_input += x1.to_bytes((x1.bit_length() + 7) // 8, 'big')

        m.update(h_input)
        c_bytes = m.digest()
        return int.from_bytes(c_bytes, 'big') == share.c

    @staticmethod
    def compute_lambda( quorum, j, delta ):
        nom = delta
        den = 1
        for j_prime in quorum:
            if j_prime != j:
                nom *= (0 - j_prime) 
                den *= (j - j_prime)
        return nom//den

    def combine_shares(self, shares, ciphertext):
        
        if( len(ciphertext) > self.rsa_ct_len ):
            x = int.from_bytes(ciphertext[:self.rsa_ct_len], 'big')
        else:
            x = int.from_bytes(ciphertext, 'big')

        delta = math.factorial(self.l)
        e_p = 4* delta * delta
        g, a, b = egcd( e_p, self.e )
        assert(g == 1)
        
        assert( len(shares) >= self.k )

        quorum = []
        for i in range(self.k):
            quorum.append(shares[i].i)

        w = 1
        for s in shares[:self.k]:
            x_i = s.x_i
            j = s.i

            lamb = PublicKey.compute_lambda(quorum, j, delta)
            if(lamb<0):
                x_i_inv = pow( x_i, -1, self.n )
                assert(x_i_inv * x_i % self.n == 1)
                w *= pow(x_i_inv, 2*(-lamb), self.n)
            else:
                w *= pow(x_i, 2*lamb, self.n)

        assert(pow(w, self.e, self.n) == pow(x, e_p, self.n))

        if( a < 0 ):
            p1 = pow( pow(w,-1,self.n), -a, self.n)
        else:
            p1 = pow(w, a, self.n)

        if( b < 0 ):
            p2 = pow( pow(x,-1,self.n), -b, self.n)
        else:
            p2 = pow(x, b, self.n)

        pt = p1*p2 % self.n
        
        pt = pt.to_bytes( ((pt.bit_length() + 7) // 8 ) , 'big')

        #remove padding        
        index = pt[1:].find(b"\x00") # search second 0x00 that delimits end of padding
        pt = pt[2+index:]        
        
        if ( len(ciphertext) <= self.rsa_ct_len ): # we needed more than 3 bytes of padding, so the plaintext fit into the asymmetric encryption part
            return pt
        
        # decrypt and verify AES encrypted part
            
        aes_key = pt[:self.AES_KEYSIZE]
        aes = AES.new(aes_key, AES.MODE_GCM, nonce=b"\0" * 16)
        added_ct = ciphertext[self.rsa_ct_len:-aes._mac_len]
        tag = ciphertext[-aes._mac_len:]
        added_pt = aes.decrypt_and_verify( added_ct, tag )
        
        ret = bytes(list(pt[32:]) + list(added_pt))
                 
        return ret

class PrivateKey:

    def __init__(self, pubkey, s_i, i):
        self.pubkey = deepcopy(pubkey)
        self.s_i = s_i
        self.i =i

    @classmethod
    def from_file(cls, path):
        with open(path, "rb") as f:
            serialized_key = f.read()
        return cls.deserialize(serialized_key)

    def to_file(self, path):
        content = self.serialize()
        with open(path, "wb") as f:
            f.write(content)

    @classmethod
    def deserialize(cls, serialized_key):
        json_key = json.loads(serialized_key)
        bytes_pubkey = binascii.unhexlify( json_key["pubkey"] )
        return cls( PublicKey.deserialize(bytes_pubkey) ,json_key["s_i"],json_key["i"])

    def serialize(self):
        json_pubkey = self.pubkey.serialize()
        json_privkey = { "pubkey":json_pubkey.hex(), "s_i":self.s_i, "i":self.i }
        return json.dumps(json_privkey).encode('utf-8')

    def compute_share(self, ciphertext):

        max_ct_len = self.pubkey.n.bit_length() // 8

        x = int.from_bytes(ciphertext, 'big')
        if( len(ciphertext) > max_ct_len ):
            x = int.from_bytes(ciphertext[:max_ct_len], 'big')

        delta = math.factorial(self.pubkey.l)
        x_i = pow( x, 2*delta*self.s_i, self.pubkey.n )
        
        x_tilde = pow( x, 4*delta, self.pubkey.n )    
        r = random.randint( 0, 2**(256) )
        v_p = pow(self.pubkey.v, r, self.pubkey.n)
        x_p = pow(x_tilde, r, self.pubkey.n)
        m = hashlib.sha3_256()
        h_input = self.pubkey.v.to_bytes((self.pubkey.v.bit_length() + 7) // 8, 'big')
        h_input += x_tilde.to_bytes((x_tilde.bit_length() + 7) // 8, 'big')
        h_input += self.pubkey.V_i[self.i-1].to_bytes((self.pubkey.V_i[self.i-1].bit_length() + 7) // 8, 'big')
        x_sq = pow(x_i,2)
        h_input += x_sq.to_bytes((x_sq.bit_length() + 7) // 8, 'big')
        
        h_input += v_p.to_bytes((v_p.bit_length() + 7) // 8, 'big')
        h_input += x_p.to_bytes((x_p.bit_length() + 7) // 8, 'big')

        m.update(h_input)
        c_bytes = m.digest()
        c = int.from_bytes(c_bytes, 'big')

        z = self.s_i*c+r

        share = DecryptionShare( self.i, x_i, c, z )

        return share

class DecryptionShare:

    def __init__(self, i, x_i, c, z):
        self.i = i
        self.x_i = x_i
        self.c = c
        self.z = z

    @classmethod
    def deserialize(cls, serialized_share):
        json_share = json.loads(serialized_share)
        return cls(json_share["i"],json_share["x_i"],json_share["c"],json_share["z"])

    def serialize(self):
        json_share = { "i":self.i, "x_i":self.x_i, "c":self.c, "z":self.z }
        return json.dumps(json_share).encode('utf-8')
    
    @classmethod
    def from_file(cls, path):
        with open(path, "rb") as f:
            serialized_share = f.read()
        return cls.deserialize(serialized_share)

    def to_file(self, path):
        serialized_share = self.serialize()
        with open(path, "wb") as f:
            f.write(serialized_share)


# k is threshold and l is amount of servers
def generate_key_shares( k, l, key_security=2048, e=65537 ):

    random.seed()

    prime_size = int(key_security/2)
    
    # the paper originally calls for p and q to be safe primes, however with todays typical key sizes this is no longer considered necessary for RSA to be secure
    n = None
    while n is None or n.bit_length() < key_security:
        p = number.getPrime(prime_size)
        q = number.getPrime(prime_size)
                
        p_p = (p-1)//2
        q_p = (q-1)//2
            
        n = p * q
        m = p_p * q_p
    
        try:
            d = pow( e, -1, m )
        except ValueError:
            n=None
            continue
            
        assert( (d*e)%m == 1)

    a = [d]
    for i in range(1, k):
        a.append( random.randint( 0, m-1 ) )

    S_i = []
    for i in range(1, l+1):
        s_i = 0
        for j in range(len(a)):
            s_i += (a[j] * pow(i, j, m)) % m

        S_i.append(s_i)

    gen_v = pow( random.randint(2, n), 2, n )
    gcd = math.gcd( gen_v-1, n )
    while gcd != 1:
        gen_v = pow( random.randint(2, n), 2, n )
        gcd = math.gcd( gen_v-1, n )

    v = pow( gen_v, random.randint(0, n), n )

    V_i = []
    for i in range(1, l+1):
        V_i.append( pow(v, S_i[i-1], n ) )

    pubkey = PublicKey( n, e, v, V_i, l, k )

    privkeys = []
    for i in range(len(S_i)):
        privkeys.append(PrivateKey(pubkey, S_i[i], i+1))

    return pubkey, privkeys