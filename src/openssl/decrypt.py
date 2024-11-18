from thRSAhold import PrivateKey, PublicKey

with open("./ciphertext", mode='rb') as file: # b is important -> binary
    ciphertext = file.read()

pubkey = PublicKey.from_file("./keys/pubkey.key")

privkeys = []
for i in range(5):
    privkeys.append( PrivateKey.from_file(f"./keys/privkey{i}.key") )
    

shares = []
for i in range(5):
    s = privkeys[i].compute_share( ciphertext )
    shares.append(s)

for i in range(5):
    pubkey.verify_zkp(shares[i], ciphertext)

plaintext = pubkey.combine_shares(shares, ciphertext)

print( plaintext )