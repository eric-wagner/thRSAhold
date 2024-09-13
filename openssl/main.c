#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "thRSAhold.h"
 
int main(int argc, char *argv[]){

    EVP_PKEY* key = thRSAhold_init("./keys/pubkey.pem");

    int pt_len = 1000;
    unsigned char pt[pt_len];
    memset(pt, 'a', pt_len);

    int ct_len = thRSAhold_expected_ct_len(pt_len);
    unsigned char* ct = (unsigned char*) malloc(ct_len);

    if( !thRSAhold_encrypt( key, pt, pt_len, ct, ct_len ) ){
        printf("Encryption error");
    }

    thRSAhold_deinit(key);

    FILE* fp = fopen ( "./ciphertext" , "wb" );
    if( !fp ){
        printf("Couldn't open file");
        exit(0);
    }
    fwrite(ct, 1, ct_len, fp);
    fclose(fp);

}