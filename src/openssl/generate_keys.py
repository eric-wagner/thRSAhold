from thRSAhold import PublicKey,generate_key_shares
import os
import glob

pubkey, privkeys = generate_key_shares(5, 10)

files = glob.glob('./keys/*')
for f in files:
    os.remove(f)

pubkey.to_file("./keys/pubkey.key")
pubkey.to_pem_file("./keys/pubkey.pem")

for i,privkey in enumerate(privkeys):
    privkey.to_file(f"./keys/privkey{i}.key")