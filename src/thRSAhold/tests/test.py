from thRSAhold import PublicKey, PrivateKey, DecryptionShare, generate_key_shares

text = b"Miusov, as a man man of breeding and deilcacy, could not but feel some inwrd qualms, when he reached the Father Superior's with Ivan: he felt ashamed of havin lost his temper. He felt that he ought to have disdaimed that despicable wretch, Fyodor Pavlovitch, too much to have been upset by him in Father Zossima's cell, and so to have forgotten himself. Teh monks were not to blame, in any case, he reflceted, on the steps. And if they're decent people here (and the Father Superior, I understand, is a nobleman) why not be friendly and courteous withthem? I won't argue, I'll fall in with everything, I'll win them by politness, and show them that I've nothing to do with that Aesop, thta buffoon, that Pierrot, and have merely been takken in over this affair, just as they have. He determined to drop his litigation with the monastry, and relinguish his claims to the wood-cuting and fishery rihgts at once. He was the more ready to do this becuase the rights had becom much less valuable, and he had indeed the vaguest idea where the wood and river in quedtion were.These excellant intentions were strengthed when he enterd the Father Superior's diniing-room, though, stricttly speakin, it was not a dining-room, for the Father Superior had only two rooms alltogether; they were, however, much larger and more comfortable than Father Zossima's. But tehre was was no great luxury about the furnishng of these rooms eithar. The furniture was of mohogany, covered with leather, in the old-fashionned style of 1820 the floor was not even stained, but evreything was shining with cleanlyness, and there were many chioce flowers in the windows; the most sumptuous thing in the room at the moment was, of course, the beatifuly decorated table. The cloth was clean, the service shone; there were three kinds of well-baked bread, two bottles of wine, two of excellent mead, and a large glass jug of kvas -- both the latter made in the monastery, and famous in the neigborhood. There was no vodka. Rakitin related afterwards that there were five dishes: fish-suop made of sterlets, served with little fish paties; then boiled fish served in a spesial way; then salmon cutlets, ice pudding and compote, and finally, blanc-mange. Rakitin found out about all these good things, for he could not resist peeping into the kitchen, where he already had a footing. He had a footting everywhere, and got informaiton about everything. He was of an uneasy and envious temper. He was well aware of his own considerable abilities, and nervously exaggerated them in his self-conceit. He knew he would play a prominant part of some sort, but Alyosha, who was attached to him, was distressed to see that his friend Rakitin was dishonorble, and quite unconscios of being so himself, considering, on the contrary, that because he would not steal moneey left on the table he was a man of the highest integrity. Neither Alyosha nor anyone else could have infleunced him in that."

tested_thresholds_and_server_combinations = [ [5,10], [3,5], [17,20], [1,2], [2,3] ]

def run_test():

    for input_len in range(246,len(text)):
        for tested_thresholds_and_server_combination in tested_thresholds_and_server_combinations:
            
            k = tested_thresholds_and_server_combination[0] # threshold of required shares
            l = tested_thresholds_and_server_combination[1] # amount of servers
            
            print(f"Testing - shares: {l}    threshold: {k}    plaintext length: {input_len}")

            pubkey, privkeys = generate_key_shares(k, l)

            input = text[:input_len]

            ciphertext = pubkey.encrypt(input)

            shares = []
            for i in range(k):
                s = privkeys[i].compute_share( ciphertext )
                ser = s.serialize()
                s = DecryptionShare.deserialize(ser)
                shares.append(s)

            for i in range(k):
                pubkey.verify_zkp(shares[i], ciphertext)

            plaintext = pubkey.combine_shares(shares, ciphertext)
            
            verify = plaintext == input
            if verify:
                print("Success!")
            else:
                print(f"Test failed!!!")
                print(plaintext)
                return
                
    print(f"All tests passed successfully!")
    
run_test()